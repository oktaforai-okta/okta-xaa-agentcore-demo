"""FastAPI BFF: signs the user in to Okta and invokes the agent.

Two things make this more than boilerplate:

  1. **It signs in through the AI Agent's linked app**, authenticating with
     `private_key_jwt` because that app has no client secret. Okta's *User access*
     binding means this is the app the user must be signed in to for the agent to act.
  2. **It does not need to send an ID token.** Okta's Machine access configuration lets
     ID-JAG leg 1 exchange the access token the gateway already validated, so the chain
     carries one credential rather than two. Set `SEND_ID_TOKEN=true` only if the
     interceptor runs in `XAA_LEG1_SUBJECT=id_token` mode.

**Where the tokens actually live, stated precisely.** Starlette's SessionMiddleware
serialises the session as base64 JSON and SIGNS it with FRONTEND_SESSION_SECRET -- it does
not encrypt it. Because this BFF keeps the access and ID tokens in the session, they ride
in the cookie and anyone who can read that cookie can base64-decode both. The signature
stops tampering, not reading.

That is acceptable for a localhost sample and not acceptable in production. The cookie is
HttpOnly and SameSite=Lax (so script and cross-site reads are blocked) but deliberately NOT
Secure, so it works over http://localhost. Before serving this anywhere real:

  * set `https_only=True` on SessionMiddleware, and
  * keep the tokens OUT of the cookie -- hold them server-side (cache, database, or a
    secrets store) keyed by an opaque session id, which is the usual BFF pattern.

Earlier versions of this file claimed "tokens never reach the browser". That was wrong, and
worth correcting in a sample about token handling.

**The chat transcript does NOT ride in the cookie.** It is held server-side in
`_TRANSCRIPTS`, keyed by an opaque id that is the only chat-related thing in the session --
the pattern recommended just above, applied here because a transcript would also blow the
4KB cookie limit within a few turns. The runtime session id lives beside it: AgentCore
routes invokes carrying the same id to the same microVM, which is what gives the agent its
conversation memory. Both are per-process, so a restart ends every conversation; that is
the right shape for a sample and the wrong one for a deployment.

    python frontend/app.py        # http://localhost:8000
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx
import jwt as pyjwt
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

SAMPLE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SAMPLE_ROOT / "deploy"))
from _common import env, load_env, must_env, okta_org_url

load_env()

FRONTEND_DIR = Path(__file__).resolve().parent
ORG = okta_org_url()
AS1 = must_env("AGENTCORE_AS_ISSUER")
CLIENT_ID = must_env("LOGIN_CLIENT_ID")
AUTH_METHOD = env("LOGIN_CLIENT_AUTH_METHOD", "private_key_jwt")
REDIRECT_URI = env("FRONTEND_REDIRECT_URI", "http://localhost:8000/auth/callback")
SCOPES = f"openid profile email {env('SCOPE_AGENT_ACCESS', 'agent.access')}"
RUNTIME_URL = env("AGENT_RUNTIME_INVOKE_URL", "")
KEY_PATH = SAMPLE_ROOT / "scripts" / "keys" / "okta_private_key.pem"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
DEFAULT_PROMPT = "What is on my todo list?"
AGENTCORE_AUDIENCE = env("AGENTCORE_AUDIENCE")
# AgentCore's HTTP protocol session header. It is a protocol header, not a custom one,
# so it does NOT need to appear in the runtime's requestHeaderAllowlist -- which could
# not carry it anyway, since that list rejects x-amzn-* names.
SESSION_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"

app = FastAPI(title="Okta XAA delegation chain sample")
app.add_middleware(SessionMiddleware, secret_key=must_env("FRONTEND_SESSION_SECRET"), same_site="lax")
templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))

# Server-side, keyed by the opaque id in the cookie. See the module docstring for why
# neither of these may live in the cookie itself.
_TRANSCRIPTS: dict[str, list[dict[str, str]]] = {}
_RUNTIME_SESSIONS: dict[str, str] = {}
_MAX_TURNS = 100


def chat_id(request: Request) -> str:
    """The opaque id tying this browser to its server-side transcript."""
    cid = request.session.get("chat_id")
    if not cid:
        cid = secrets.token_urlsafe(32)
        request.session["chat_id"] = cid
    return cid


def runtime_session(cid: str) -> str:
    """The AgentCore session id for this chat, created once and then reused.

    `runtimeSessionId` must be at least 33 characters and match
    `[a-zA-Z0-9][a-zA-Z0-9-_]*`; a shorter value is a 400. token_hex gives 48 hex
    characters, which satisfies both -- token_urlsafe does not, because it can begin
    with `-` or `_`.
    """
    sid = _RUNTIME_SESSIONS.get(cid)
    if not sid:
        sid = secrets.token_hex(24)
        _RUNTIME_SESSIONS[cid] = sid
    return sid


def append(cid: str, sender: str, message: str) -> None:
    turns = _TRANSCRIPTS.setdefault(cid, [])
    turns.append({"sender": sender, "message": message})
    del turns[:-_MAX_TURNS]


def reset_chat(cid: str) -> None:
    """Drop the transcript and the runtime session id together.

    Both, not just the transcript: leaving the session id would let the agent keep
    answering from a history the user believes they have cleared.
    """
    _TRANSCRIPTS.pop(cid, None)
    _RUNTIME_SESSIONS.pop(cid, None)


def sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


def sse_error(message: str) -> StreamingResponse:
    """One error event as a complete stream, for failures known before the call."""

    async def once():
        yield sse({"type": "error", "message": message})
        yield sse({"type": "turn.end", "ok": False})

    return StreamingResponse(once(), media_type="text/event-stream")


def parse_event(raw: str) -> dict[str, Any] | None:
    """Decode one `data:` payload, tolerating what the runtime may inject.

    The SDK emits its own shape on an unhandled exception inside the agent
    (`{"error": ..., "error_type": ...}`), so that is translated rather than dropped.
    """
    try:
        event = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    if "type" not in event:
        if "error" in event:
            return {"type": "error", "message": f"the agent failed ({event.get('error_type', 'error')})."}
        return None
    return event


def runtime_error(status: int, kind: str, body: str) -> dict[str, Any]:
    """Map an InvokeAgentRuntime failure to something actionable.

    409 is the one worth special-casing: AgentCore returns it while a session is being
    provisioned or torn down, and it clears on its own.
    """
    if status == 409:
        return {"type": "error", "message": "the session was still starting up. Send that again."}
    if status == 404:
        return {
            "type": "error",
            "message": (
                "the runtime returned 404. AGENT_RUNTIME_INVOKE_URL must end with "
                "?qualifier=DEFAULT."
            ),
        }
    detail = f" ({kind})" if kind else ""
    return {"type": "error", "message": f"the runtime returned HTTP {status}{detail}. {body[:300]}"}


def client_auth(form: dict[str, Any]) -> dict[str, Any]:
    """Add client authentication to a token request.

    The AI Agent's linked app uses Public/private key, so there is no secret to send;
    we sign an assertion with the same key the interceptor uses for the ID-JAG legs.
    """
    if AUTH_METHOD != "private_key_jwt":
        form["client_secret"] = must_env("LOGIN_CLIENT_SECRET")
        return form
    now = int(time.time())
    form["client_assertion_type"] = CLIENT_ASSERTION_TYPE
    form["client_assertion"] = pyjwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": f"{AS1}/v1/token",
            "iat": now,
            "exp": now + 300,
            "jti": secrets.token_urlsafe(16),
        },
        KEY_PATH.read_text(),
        algorithm="RS256",
        headers={"kid": must_env("AI_AGENT_KEY_KID")},
    )
    return form


def claims(token: str) -> dict[str, Any]:
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, IndexError, json.JSONDecodeError):
        return {}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={
            "user": user,
            "runtime_configured": bool(RUNTIME_URL),
        },
    )


@app.get("/auth/login")
async def login(request: Request):
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)
    request.session["pkce_verifier"] = verifier
    request.session["auth_state"] = state
    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": SCOPES,
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://xaa-agentcore.example.com"
        }
    )
    return RedirectResponse(f"{AS1}/v1/authorize?{query}")


@app.get("/auth/callback")
async def callback(request: Request):
    if request.query_params.get("error"):
        return HTMLResponse(
            f"<h3>Okta returned an error</h3><pre>{request.query_params.get('error')}: "
            f"{request.query_params.get('error_description', '')}</pre>",
            status_code=400,
        )
    code = request.query_params.get("code")
    if not code or request.query_params.get("state") != request.session.get("auth_state"):
        return HTMLResponse("<h3>Invalid OAuth callback (missing code or state mismatch)</h3>", 400)

    form = client_auth(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": request.session.get("pkce_verifier", ""),
            "client_id": CLIENT_ID,
        }
    )
    async with httpx.AsyncClient(timeout=45) as http:
        resp = await http.post(f"{AS1}/v1/token", data=form)
    if resp.status_code >= 400:
        return HTMLResponse(f"<h3>Token exchange failed</h3><pre>{resp.text[:600]}</pre>", 400)
    tokens = resp.json()

    # Both tokens go into the signed session cookie -- see the module docstring. T_user
    # invokes the agent; the ID token is kept only for the id_token fallback mode and the
    # interceptor needs for ID-JAG leg 1.
    request.session["access_token"] = tokens["access_token"]
    request.session["id_token"] = tokens["id_token"]
    request.session["user"] = claims(tokens["access_token"]).get("sub", "unknown")
    request.session.pop("pkce_verifier", None)
    request.session.pop("auth_state", None)
    return RedirectResponse("/")


@app.get("/auth/logout")
async def logout(request: Request):
    # Clear the server-side state too, or the next sign-in in this browser would
    # inherit the previous user's transcript and the agent's memory of it.
    reset_chat(chat_id(request))
    request.session.clear()
    return RedirectResponse("/")


@app.get("/debug/token", response_class=HTMLResponse)
async def debug_token(request: Request):
    """Show the session's token claims. Debug route -- remove it if you reuse this."""
    if not request.session.get("access_token"):
        return RedirectResponse("/auth/login")
    return templates.TemplateResponse(
        request=request,
        name="token.html",
        context={
            "user": request.session.get("user"),
            "access": claims(request.session["access_token"]),
            "id": claims(request.session["id_token"]),
        },
    )


@app.get("/chat", response_class=HTMLResponse)
async def chat(request: Request):
    if not request.session.get("access_token"):
        return RedirectResponse("/auth/login")
    return templates.TemplateResponse(
        request=request,
        name="chat.html",
        context={
            "user": request.session.get("user"),
            "default_prompt": DEFAULT_PROMPT,
            "runtime_configured": bool(RUNTIME_URL),
            "messages": _TRANSCRIPTS.get(chat_id(request), []),
        },
    )


@app.post("/chat/clear")
async def chat_clear(request: Request):
    """Forget the transcript AND the runtime session, so the agent starts clean too."""
    reset_chat(chat_id(request))
    return RedirectResponse("/chat", status_code=303)


@app.post("/chat/send")
async def chat_send(request: Request, prompt: str = Form(default=DEFAULT_PROMPT)):
    """Relay one turn, streaming the agent's SSE straight through to the browser.

    The runtime is called with httpx rather than boto3 deliberately: the AWS SDKs buffer
    the whole EventStream before handing over the first chunk, which would defeat the
    streaming this page exists to show. A direct signed HTTPS request does not.
    """
    if not request.session.get("access_token"):
        return JSONResponse({"error": "not signed in"}, status_code=401)

    prompt = prompt.strip()
    if not prompt:
        return JSONResponse({"error": "empty prompt"}, status_code=400)

    if not RUNTIME_URL:
        return sse_error(
            "AGENT_RUNTIME_INVOKE_URL is not set in .env. Deploy the agent, then copy the "
            "invoke URL from `agentcore status`. It must end with ?qualifier=DEFAULT, or "
            "the call returns 404 UnknownOperationException."
        )

    cid = chat_id(request)
    # No id_token here. The agent mints T_gateway and the gateway's interceptor exchanges
    # THAT at ID-JAG leg 1, which Okta's Machine access configuration authorises. Set
    # SEND_ID_TOKEN=true to also forward it, which orgs running the interceptor in
    # id_token mode need.
    payload: dict[str, Any] = {"prompt": prompt}
    if env("SEND_ID_TOKEN", "").lower() == "true":
        payload["id_token"] = request.session["id_token"]
        payload["access_token"] = request.session["access_token"]
    headers = {
        "Authorization": f"Bearer {request.session['access_token']}",
        "Content-Type": "application/json",
        # Pins the turn to one microVM, which is what lets the agent remember the
        # conversation. Drop it and every turn starts from nothing.
        SESSION_HEADER: runtime_session(cid),
    }

    append(cid, "user", prompt)
    return StreamingResponse(relay(cid, payload, headers), media_type="text/event-stream")


async def relay(cid: str, payload: dict[str, Any], headers: dict[str, str]):
    """Forward the runtime's SSE events, recording the answer as it goes.

    Each upstream `data:` line is re-emitted verbatim -- the agent already decided what
    is safe to show, and re-encoding here would only add a place to get it wrong. The
    text fragments are accumulated so a page refresh can redraw the turn.
    """
    answer: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0)) as http:
            async with http.stream("POST", RUNTIME_URL, json=payload, headers=headers) as resp:
                if resp.status_code >= 400:
                    body = (await resp.aread()).decode(errors="replace")
                    yield sse(runtime_error(resp.status_code, resp.headers.get("x-amzn-errortype", ""), body))
                    yield sse({"type": "turn.end", "ok": False})
                    return
                if "text/event-stream" not in resp.headers.get("content-type", ""):
                    # A JSON body here means the agent returned instead of yielding --
                    # usually an older build that has not been redeployed.
                    body = (await resp.aread()).decode(errors="replace")[:600]
                    yield sse(
                        {
                            "type": "error",
                            "message": (
                                "the runtime did not stream. Redeploy the agent so it "
                                f"yields SSE events. It replied: {body}"
                            ),
                        }
                    )
                    yield sse({"type": "turn.end", "ok": False})
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    raw = line[5:].strip()
                    event = parse_event(raw)
                    if event is None:
                        continue
                    if event.get("type") == "text":
                        answer.append(event.get("data", ""))
                    yield sse(event)
    except httpx.HTTPError as exc:
        yield sse({"type": "error", "message": f"could not reach the agent runtime ({type(exc).__name__})."})
        yield sse({"type": "turn.end", "ok": False})
    finally:
        if answer:
            append(cid, "agent", "".join(answer))


if __name__ == "__main__":
    import uvicorn

    host = env("FRONTEND_HOST", "localhost")
    port = int(env("FRONTEND_PORT", "8000"))
    print(f"signing in via {CLIENT_ID} ({AUTH_METHOD}) at {AS1}")
    print(f"agent runtime: {RUNTIME_URL or '<not deployed yet>'}")
    print(f"open http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)

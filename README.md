# Frontend (BFF)

A small FastAPI **backend-for-frontend**. It signs the user in to Okta (OIDC + PKCE,
authenticating with `private_key_jwt`), keeps the tokens out of page JavaScript, and
streams the agent's replies to a chat UI.

It talks to exactly two things, both over HTTPS:

- **Okta** — the AgentCore custom authorization server, for sign-in and token exchange.
- **The AgentCore Runtime** — invoked with the user's access token as a bearer token.

It needs **no AWS credentials**. The agent, gateway, interceptor and todo API stay in
AWS and must already be deployed (see the [top-level README](../README.md)).

## Routes

| Route | What it does |
|---|---|
| `GET /` | Home page, shows sign-in state |
| `GET /auth/login` | Starts the Okta authorization-code + PKCE flow |
| `GET /auth/callback` | Okta redirect target; exchanges the code for tokens |
| `GET /auth/logout` | Clears the session and the server-side transcript |
| `GET /chat` | Streaming chat UI |
| `POST /chat/send` | Sends a prompt to the agent runtime, streams the reply (SSE) |
| `POST /chat/clear` | Drops the transcript and the runtime session id |
| `GET /debug/token` | Shows decoded token claims — **remove before exposing publicly** |

## Environment variables

The app loads `../.env` (the repo-root file the deploy scripts write) on startup.
Values that are already in the process environment **win** over the file, so on a host
like Render you can set everything as real environment variables instead.

### Required

| Variable | Example | Where it comes from |
|---|---|---|
| `OKTA_ORG_URL` | `https://your-tenant.okta.com` | Your Okta org (app-facing host, not `-admin`) |
| `AGENTCORE_AS_ISSUER` | `https://your-tenant.okta.com/oauth2/aus…` | Written by `deploy/00_create_okta_apps.py` |
| `AGENTCORE_AUDIENCE` | `https://xaa-agentcore.example.com` | Must match the custom AS audience |
| `LOGIN_CLIENT_ID` | `0oa…` | The AI Agent's linked login app (`00_create_okta_apps.py`) |
| `AI_AGENT_KEY_KID` | `abc123…` | `kid` of the AI Agent's public key in Okta |
| `FRONTEND_SESSION_SECRET` | 64 hex chars | Generate: `python -c 'import secrets;print(secrets.token_hex(32))'` |
| `AGENT_RUNTIME_INVOKE_URL` | `https://bedrock-agentcore.<region>.amazonaws.com/runtimes/…/invocations?qualifier=DEFAULT` | `agentcore status`. **Must end with `?qualifier=DEFAULT`** or every invoke 404s |

`AGENT_RUNTIME_INVOKE_URL` is technically optional — the app starts without it — but
chat returns an error until it is set.

### Private key file

With the default `private_key_jwt` auth method the app signs its client assertion with
the AI Agent's private key, read from a **fixed path**:

```
scripts/keys/okta_private_key.pem      # relative to the repo root
```

This path is gitignored. Never commit the key.

### Optional

| Variable | Default | Purpose |
|---|---|---|
| `FRONTEND_REDIRECT_URI` | `http://localhost:8000/auth/callback` | Must exactly match a sign-in redirect URI on the Okta login app |
| `LOGIN_CLIENT_AUTH_METHOD` | `private_key_jwt` | Set to anything else to use a client secret instead of the key |
| `LOGIN_CLIENT_SECRET` | — | Required only when `LOGIN_CLIENT_AUTH_METHOD` is not `private_key_jwt` |
| `SCOPE_AGENT_ACCESS` | `agent.access` | Custom scope that allows invoking the runtime |
| `SEND_ID_TOKEN` | *(empty)* | `true` forwards the ID token too; only for interceptor `XAA_LEG1_SUBJECT=id_token` mode |
| `FRONTEND_HOST` | `localhost` | Bind host, used only by `python frontend/app.py` |
| `FRONTEND_PORT` | `8000` | Bind port, used only by `python frontend/app.py` |
| `XAA_ENV_FILE` | `.env` | Alternate env file; absolute path, or relative to the repo root |

## Run locally

From the repo root, after the deploy steps have populated `.env`:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python frontend/app.py            # http://localhost:8000
```

## Deploy on Render

Create a **Web Service** from the **whole repository** — not just `frontend/`. The app
imports `deploy/_common.py` and resolves paths from the repo root.

**Build command**

```bash
pip install -r requirements.txt
```

**Start command**

```bash
mkdir -p scripts/keys && cp /etc/secrets/okta_private_key.pem scripts/keys/ && \
uvicorn app:app --app-dir frontend --host 0.0.0.0 --port $PORT \
  --proxy-headers --forwarded-allow-ips='*'
```

**Secret files** (Environment → Secret Files; Render mounts them under `/etc/secrets/`)

| Filename | Contents |
|---|---|
| `okta_private_key.pem` | The AI Agent's private key (the start command copies it into place) |
| `frontend.env` | The env file the app requires at startup — see below |

The app exits if its env file is missing. Either put all the variables above into
`frontend.env`, or set them as normal Render environment variables and leave
`frontend.env` with just a comment line. In both cases set:

```
XAA_ENV_FILE=/etc/secrets/frontend.env
FRONTEND_REDIRECT_URI=https://<your-service>.onrender.com/auth/callback
```

**In Okta**, add `https://<your-service>.onrender.com/auth/callback` to the login
app's *Sign-in redirect URIs*.

Do **not** put admin credentials such as `OKTA_API_TOKEN` or `AGENT_APP_CLIENT_SECRET`
on Render. The frontend doesn't use them.

## Known limitations before going public

- **Tokens ride in the session cookie.** The cookie is signed, not encrypted, so anyone
  holding it can read the access and ID tokens. For real users, store the tokens
  server-side, keyed by an opaque session id.
- **The cookie is not `Secure`.** It is set without `https_only=True` so it works over
  `http://localhost`. Enable that on `SessionMiddleware` for any HTTPS deployment.
- **Chat state is in memory.** Transcripts and runtime session ids are lost on every
  restart, redeploy, or free-tier spin-down, and they are not shared between instances.
  Run a single instance.
- **`/debug/token` exposes token claims.** Remove it before exposing the app.

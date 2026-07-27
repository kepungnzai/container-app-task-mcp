# MCP Tasks Server

A simple MCP (Model Context Protocol) Tasks server with CIMD (Client Identity and Metadata Discovery) authentication, built with FastAPI and FastMCP.

## Features

- **MCP Tools**: `list_tasks`, `get_task`, `create_task`, `toggle_task_complete`, `delete_task`
- **CIMD OAuth 2.0 Authentication**: JWT-based access tokens with RSA/RS256 signing
- **Token lifecycle**: Authorization code grant, token refresh, token revocation
- **JWKS endpoint**: Public key distribution for token verification
- **OAuth metadata discovery**: Standard `.well-known` endpoints
- **Toggle for local development**: Disable authentication via environment variable

## Quick Start (Local Development)

### Prerequisites

- Python 3.13+
- `uv` package manager (recommended) or `pip`

### Setup

```bash
# Clone and enter the project
cd container-app-task-mcp

# Create virtual environment
uv venv
source .venv/bin/activate  # Linux/Mac
# or: .venv\Scripts\activate  # Windows

# Install dependencies
uv sync
# or: pip install -e .
```

### Run with Authentication Disabled (for local development)

```bash
# Disable auth – perfect for local testing
export MCP_AUTH_DISABLED=true

# Start the server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### Run with Authentication Enabled

```bash
# Auth is enabled by default; optionally configure:
export MCP_AUTH_ISSUER_URL=http://localhost:8000
export MCP_CLIENT_REGISTRATION_FILE=oauth.json

# Start the server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### Verify the Server

```bash
# Health check
curl http://localhost:8000/health

# JWKS endpoint (returns public keys for JWT verification)
curl http://localhost:8000/.well-known/jwks.json

# OAuth metadata discovery
curl http://localhost:8000/.well-known/oauth-authorization-server

# Call an MCP tool (when auth is disabled)
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tasks","arguments":{}}}'
```

## CIMD Authentication

### Overview

The server implements the **Client Identity and Metadata Discovery (CIMD)** OAuth 2.0 authorization flow as specified by the MCP protocol. When authentication is enabled, all MCP tool calls require a valid Bearer access token.

### Architecture

```
Client  -->  /authorize  -->  CIMDAuthProvider  -->  redirect_uri?code=...
Client  -->  /token      -->  CIMDAuthProvider  -->  { access_token, refresh_token }
Client  -->  /mcp        -->  FastMCP           -->  (requires Bearer token)
Client  -->  /revoke     -->  CIMDAuthProvider  -->  200 OK
```

### Key Components

| File | Purpose |
|------|---------|
| `auth_provider.py` | `CIMDAuthProvider` class implementing the full OAuth 2.0 authorization server |
| `mcp_server.py` | Creates FastMCP instance with optional auth configuration |
| `main.py` | FastAPI app with health, JWKS, OAuth metadata, and MCP endpoints |
| `oauth.json` | Pre-registered OAuth client configuration |

### Token Details

- **Access tokens**: RSA/RS256 signed JWTs, 1-hour lifetime, contain `jti` for revocation
- **Refresh tokens**: Opaque tokens, 30-day lifetime, rotated on each use
- **Authorization codes**: Single-use, 10-minute lifetime
- **Token revocation**: Both local store removal + JWT `jti` blacklist

### Client Registration

Pre-registered clients are loaded from the file specified by `MCP_CLIENT_REGISTRATION_FILE` (default: `oauth.json`).

Example `oauth.json`:
```json
{
  "client_id": "https://legitimate-pizza-app.com/.well-known/oauth.json",
  "client_name": "Pizza Ordering App",
  "client_uri": "https://legitimate-pizza-app.com",
  "redirect_uris": ["https://legitimate-pizza-app.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://legitimate-pizza-app.com/.well-known/jwks.json"
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_AUTH_DISABLED` | `false` | Set to `true` to disable authentication (local development) |
| `MCP_AUTH_ISSUER_URL` | `http://localhost:8000` | OAuth issuer URL |
| `MCP_AUTH_SERVICE_DOC_URL` | *(none)* | Optional service documentation URL |
| `MCP_CLIENT_REGISTRATION_FILE` | `oauth.json` | Path to client registration JSON |
| `MCP_AUTH_ENABLE_DYNAMIC_REGISTRATION` | `false` | Enable dynamic client registration |
| `MCP_AUTH_REQUIRED_SCOPES` | `mcp://tasks` | Comma-separated required scopes |

## Deployment to Azure Container Apps

### Prerequisites

- Azure CLI (`az`) installed and logged in
- Docker installed

### Steps

```powershell
# Variables
$RESOURCE_GROUP="my-mcp-rg"
$LOCATION="australiaeast"
$ENVIRONMENT_NAME="mcp-env"
$APP_NAME="tasks-mcp-server-py"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create Container Apps environment
az containerapp env create `
  --name $ENVIRONMENT_NAME `
  --resource-group $RESOURCE_GROUP `
  --location $LOCATION

# Deploy the app
az containerapp up `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --environment $ENVIRONMENT_NAME `
  --source . `
  --ingress external `
  --target-port 8080

# Enable CORS
az containerapp ingress cors enable `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --allowed-origins "*" `
  --allowed-methods "GET,POST,DELETE,OPTIONS" `
  --allowed-headers "*"

# Verify deployment
$APP_URL = az containerapp show `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --query "properties.configuration.ingress.fqdn" `
  -o tsv

curl "https://$APP_URL/health"

# Scale down to min replicas (cost saving)
az containerapp update `
  --name $APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --min-replicas 1
```

### Production Auth Configuration

For production, set the environment variables on the container app:

```bash
az containerapp update \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --set-env-vars "MCP_AUTH_ISSUER_URL=https://$APP_URL" \
                  "MCP_AUTH_REQUIRED_SCOPES=mcp://tasks"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/.well-known/oauth-authorization-server` | GET | OAuth metadata |
| `/mcp` | POST | MCP protocol endpoint |

## Project Structure

```
.
├── auth_provider.py      # CIMD OAuth 2.0 authorization provider
├── main.py               # FastAPI application entry point
├── mcp_server.py         # MCP server with FastMCP tools
├── task_store.py         # In-memory task data store
├── oauth.json            # Pre-registered OAuth client
├── pyproject.toml        # Project dependencies
├── Dockerfile            # Container image
└── .env.example          # Environment variable reference
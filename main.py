import logging
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from mcp_server import mcp
from auth_provider import create_auth_provider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create auth provider for JWKS endpoint
_auth_provider = create_auth_provider()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())
        yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy"})


@app.get("/.well-known/jwks.json")
async def jwks():
    """Expose the JSON Web Key Set for token verification.

    This endpoint allows clients to verify JWT access tokens issued by
    the CIMD auth provider. Returns an empty key set if auth is disabled.
    """
    if _auth_provider is None:
        return JSONResponse({"keys": []})
    return JSONResponse(_auth_provider.get_jwks())


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """Expose OAuth Authorization Server metadata.

    This endpoint provides OAuth 2.0 metadata for client discovery,
    as required by the CIMD specification.
    """
    if _auth_provider is None:
        return JSONResponse({"status": "auth_disabled"})

    issuer_url = _auth_provider._issuer_url
    return JSONResponse({
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/authorize",
        "token_endpoint": f"{issuer_url}/token",
        "revocation_endpoint": f"{issuer_url}/revoke",
        "jwks_uri": f"{issuer_url}/.well-known/jwks.json",
        "scopes_supported": _auth_provider._required_scopes,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
    })


app.mount("/", mcp.streamable_http_app())

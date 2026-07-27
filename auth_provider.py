"""
CIMD (Client Identity and Metadata Discovery) Authentication Provider for MCP.

This module implements OAuth 2.0 authorization for MCP servers following the
CIMD specification, with support for client registration, token issuance,
and token verification.

Environment variables:
    MCP_AUTH_DISABLED: Set to "true" to disable authentication (for local development).
    MCP_AUTH_ISSUER_URL: The OAuth issuer URL (default: http://localhost:8000).
    MCP_AUTH_SERVICE_DOC_URL: Service documentation URL (optional).
    MCP_AUTH_REQUIRED_SCOPES: Comma-separated list of required scopes (optional).
    MCP_CLIENT_REGISTRATION_FILE: Path to client registration JSON file (default: oauth.json).
"""

import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    OAuthClientInformationFull,
    OAuthToken,
    RefreshToken,
    AccessToken,
    RegistrationError,
    RegistrationErrorCode,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions

logger = logging.getLogger(__name__)

_RSA_KEY_SIZE = 2048

_AUTHORIZATION_CODE_LIFETIME = timedelta(minutes=10)
_ACCESS_TOKEN_LIFETIME = timedelta(hours=1)
_REFRESH_TOKEN_LIFETIME = timedelta(days=30)


class CIMDAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """CIMD OAuth 2.0 Authorization Server Provider for MCP.

    Implements the OAuthAuthorizationServerProvider protocol to provide
    Client Identity and Metadata Discovery (CIMD) authentication for MCP servers.

    Supports:
    - Client registration via a JSON file (oauth.json)
    - JWT access tokens signed with RSA/RS256
    - Authorization code, access token, and refresh token lifecycle
    - Dynamic client registration (optional, disabled by default)
    - Disable via environment variable for local development
    """

    def __init__(
        self,
        issuer_url: str = "http://localhost:8000",
        service_documentation_url: str | None = None,
        client_registration_file: str = "oauth.json",
        enable_dynamic_registration: bool = False,
        required_scopes: list[str] | None = None,
    ):
        self._issuer_url = issuer_url.rstrip("/")
        self._service_documentation_url = service_documentation_url
        self._client_registration_file = client_registration_file
        self._enable_dynamic_registration = enable_dynamic_registration
        self._required_scopes = required_scopes or ["mcp://tasks"]

        # In-memory stores
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._authorization_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._revoked_token_jtis: set[str] = set()

        # Generate RSA key pair for signing JWT tokens
        self._private_key, self._public_key = self._generate_key_pair()
        self._kid = str(uuid.uuid4())[:8]

        self._load_clients()

        logger.info(
            "CIMD Auth Provider initialized (issuer=%s, dynamic_registration=%s)",
            self._issuer_url,
            self._enable_dynamic_registration,
        )

    @staticmethod
    def _generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_RSA_KEY_SIZE,
        )
        return private_key, private_key.public_key()

    def _get_jwk(self) -> dict[str, Any]:
        public_numbers = self._public_key.public_numbers()

        def _int_to_base64url(n: int) -> str:
            n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
            return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")

        return {
            "kty": "RSA",
            "n": _int_to_base64url(public_numbers.n),
            "e": _int_to_base64url(public_numbers.e),
            "alg": "RS256",
            "kid": self._kid,
            "use": "sig",
        }

    def _extract_jti_from_jwt(self, token_str: str) -> str | None:
        """Decode a JWT (without verification) and return its jti, or None."""
        try:
            headers = jwt.get_unverified_header(token_str)
            payload = jwt.decode(
                token_str,
                options={"verify_signature": False, "verify_exp": False},
            )
            return payload.get("jti")
        except Exception:
            return None

    def _load_clients(self) -> None:
        file_path = self._client_registration_file
        if not os.path.exists(file_path):
            logger.info("No client registration file found at %s", file_path)
            return

        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            entries = data if isinstance(data, list) else [data]

            for entry in entries:
                cid = entry.get("client_id")
                if not cid:
                    logger.warning("Skipping entry without client_id")
                    continue

                client = OAuthClientInformationFull(
                    client_id=cid,
                    client_name=entry.get("client_name"),
                    client_uri=entry.get("client_uri"),
                    logo_uri=entry.get("logo_uri"),
                    redirect_uris=entry.get("redirect_uris", []),
                    grant_types=entry.get("grant_types", ["authorization_code"]),
                    response_types=entry.get("response_types", ["code"]),
                    token_endpoint_auth_method=entry.get(
                        "token_endpoint_auth_method", "private_key_jwt"
                    ),
                    jwks_uri=entry.get("jwks_uri"),
                )
                self._clients[cid] = client
                logger.info("Loaded registered client: %s", cid)

        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load client registration file: %s", exc)

    # ------------------------------------------------------------------
    # Client Registration
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not self._enable_dynamic_registration:
            raise RegistrationError(
                error_code=RegistrationErrorCode.REGISTRATION_NOT_SUPPORTED,
                error_description="Dynamic client registration is not supported",
            )
        if client_info.client_id in self._clients:
            raise RegistrationError(
                error_code=RegistrationErrorCode.INVALID_CLIENT_METADATA,
                error_description=f"Client '{client_info.client_id}' is already registered",
            )
        self._clients[client_info.client_id] = client_info
        logger.info("Dynamically registered client: %s", client_info.client_id)

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.redirect_uri not in client.redirect_uris:
            raise AuthorizeError(
                error="invalid_redirect_uri",
                error_description="Redirect URI not registered for this client",
            )

        code = secrets.token_urlsafe(32)

        authorization_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=True,
            code_challenge=params.code_challenge,
            scopes=params.scopes or self._required_scopes,
            expires_at=(datetime.now(timezone.utc) + _AUTHORIZATION_CODE_LIFETIME).timestamp(),
        )
        self._authorization_codes[code] = authorization_code

        parsed = urlparse(str(params.redirect_uri))
        query_params: dict[str, str] = {"code": code, "iss": self._issuer_url}
        if params.state:
            query_params["state"] = params.state
        new_query = urlencode(query_params)
        redirect = urlunparse(parsed._replace(query=new_query))

        logger.info(
            "Authorization granted for client '%s' (code=%s...)",
            client.client_id,
            code[:8],
        )
        return redirect

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._authorization_codes.get(authorization_code)
        if code is None:
            return None
        if code.expires_at < datetime.now(timezone.utc).timestamp():
            self._authorization_codes.pop(authorization_code, None)
            return None
        if code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._authorization_codes.pop(authorization_code.code, None)

        access_token, access_token_obj = self._create_access_token(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )
        refresh_token, refresh_token_obj = self._create_refresh_token(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )

        self._access_tokens[access_token] = access_token_obj
        self._refresh_tokens[refresh_token] = refresh_token_obj

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(_ACCESS_TOKEN_LIFETIME.total_seconds()),
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes),
        )

    # ------------------------------------------------------------------
    # Token Management
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Check if the underlying JWT has been revoked (by jti)
        jti = self._extract_jti_from_jwt(token)
        if jti and jti in self._revoked_token_jtis:
            logger.debug("JWT jti=%s is revoked", jti[:8])
            return None

        stored = self._access_tokens.get(token)
        if stored is not None:
            if stored.expires_at and stored.expires_at < int(datetime.now(timezone.utc).timestamp()):
                self._access_tokens.pop(token, None)
                return None
            return stored

        # Fallback: JWT verification
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                audience=self._issuer_url,
                issuer=self._issuer_url,
                options={"verify_exp": True},
            )
            return AccessToken(
                token=token,
                client_id=payload.get("client_id", "unknown"),
                scopes=payload.get("scopes", self._required_scopes),
                expires_at=payload.get("exp", None),
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as exc:
            logger.debug("JWT verification failed: %s", exc)
            return None

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        stored = self._refresh_tokens.get(refresh_token)
        if stored is None:
            return None
        if stored.client_id != client.client_id:
            return None
        if stored.expires_at and stored.expires_at < int(datetime.now(timezone.utc).timestamp()):
            self._refresh_tokens.pop(refresh_token, None)
            return None
        return stored

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        old_token_str = next(
            (k for k, v in self._refresh_tokens.items() if v == refresh_token),
            None,
        )
        if old_token_str:
            self._refresh_tokens.pop(old_token_str, None)
        self._access_tokens = {
            k: v for k, v in self._access_tokens.items() if v.client_id != client.client_id
        }

        access_token, access_token_obj = self._create_access_token(
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
        )
        new_refresh_token, refresh_token_obj = self._create_refresh_token(
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
        )

        self._access_tokens[access_token] = access_token_obj
        self._refresh_tokens[new_refresh_token] = refresh_token_obj

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(_ACCESS_TOKEN_LIFETIME.total_seconds()),
            refresh_token=new_refresh_token,
            scope=" ".join(scopes or refresh_token.scopes),
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        token_str = token.token if hasattr(token, "token") else str(token)

        # Always blacklist the underlying JWT (even if it was already removed
        # from the local store). This prevents the JWT fallback verification
        # in load_access_token from accepting it.
        jti = self._extract_jti_from_jwt(token_str)
        if jti:
            self._revoked_token_jtis.add(jti)

        if token_str in self._access_tokens:
            cid = self._access_tokens[token_str].client_id
            self._access_tokens.pop(token_str, None)
            self._refresh_tokens = {
                k: v for k, v in self._refresh_tokens.items() if v.client_id != cid
            }
            logger.info("Revoked all tokens for client '%s' (jti=%s)", cid, jti[:8] if jti else "?")
        elif token_str in self._refresh_tokens:
            cid = self._refresh_tokens[token_str].client_id
            self._refresh_tokens.pop(token_str, None)
            self._access_tokens = {
                k: v for k, v in self._access_tokens.items() if v.client_id != cid
            }
            logger.info("Revoked all tokens for client '%s' (jti=%s)", cid, jti[:8] if jti else "?")
        elif jti:
            logger.info("Blacklisted JWT jti=%s (not in local store)", jti[:8])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_access_token(
        self, client_id: str, scopes: list[str]
    ) -> tuple[str, AccessToken]:
        now = datetime.now(timezone.utc)
        expires_at = int((now + _ACCESS_TOKEN_LIFETIME).timestamp())
        jti = str(uuid.uuid4())

        payload = {
            "iss": self._issuer_url,
            "sub": client_id,
            "aud": self._issuer_url,
            "exp": expires_at,
            "iat": int(now.timestamp()),
            "jti": jti,
            "client_id": client_id,
            "scopes": scopes,
            "token_type": "access_token",
        }

        token_str = jwt.encode(
            payload, self._private_key, algorithm="RS256",
            headers={"kid": self._kid},
        )

        access_token = AccessToken(
            token=token_str,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
        )
        return token_str, access_token

    def _create_refresh_token(
        self, client_id: str, scopes: list[str]
    ) -> tuple[str, RefreshToken]:
        now = datetime.now(timezone.utc)
        expires_at = int((now + _REFRESH_TOKEN_LIFETIME).timestamp())
        token_str = secrets.token_urlsafe(48)

        refresh_token = RefreshToken(
            token=token_str,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
        )
        return token_str, refresh_token

    def get_auth_settings(self, resource_server_url: str) -> AuthSettings:
        from pydantic import AnyHttpUrl

        return AuthSettings(
            issuer_url=AnyHttpUrl(self._issuer_url),
            service_documentation_url=(
                AnyHttpUrl(self._service_documentation_url)
                if self._service_documentation_url
                else None
            ),
            client_registration_options=ClientRegistrationOptions(
                disable_dynamic_registration=not self._enable_dynamic_registration,
            ),
            revocation_options=RevocationOptions(
                disable_revocation=False,
            ),
            required_scopes=self._required_scopes,
            resource_server_url=AnyHttpUrl(resource_server_url),
        )

    def get_jwks(self) -> dict[str, Any]:
        return {"keys": [self._get_jwk()]}


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------

def create_auth_provider() -> CIMDAuthProvider | None:
    """Create and configure a CIMDAuthProvider from environment variables.

    Returns a configured provider, or *None* when ``MCP_AUTH_DISABLED`` is
    set to ``true`` / ``1`` / ``yes`` (case-insensitive).
    """
    if os.environ.get("MCP_AUTH_DISABLED", "").lower() in ("true", "1", "yes"):
        logger.info("MCP authentication DISABLED (MCP_AUTH_DISABLED=true)")
        return None

    issuer_url = os.environ.get("MCP_AUTH_ISSUER_URL", "http://localhost:8000")
    service_documentation_url = os.environ.get("MCP_AUTH_SERVICE_DOC_URL")
    client_registration_file = os.environ.get("MCP_CLIENT_REGISTRATION_FILE", "oauth.json")
    enable_dynamic = os.environ.get("MCP_AUTH_ENABLE_DYNAMIC_REGISTRATION", "").lower() in (
        "true", "1", "yes",
    )
    required_scopes_raw = os.environ.get("MCP_AUTH_REQUIRED_SCOPES")
    required_scopes = (
        [s.strip() for s in required_scopes_raw.split(",") if s.strip()]
        if required_scopes_raw
        else None
    )

    provider = CIMDAuthProvider(
        issuer_url=issuer_url,
        service_documentation_url=service_documentation_url or None,
        client_registration_file=client_registration_file,
        enable_dynamic_registration=enable_dynamic,
        required_scopes=required_scopes,
    )

    logger.info(
        "CIMD authentication enabled (issuer=%s, clients=%d)",
        issuer_url,
        len(provider._clients),
    )
    return provider
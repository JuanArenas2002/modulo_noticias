"""Cliente OpenID Connect para Microsoft Entra ID (Authorization Code + PKCE, cliente confidencial).

Sin MSAL: el flujo son dos llamadas HTTP (urllib) y PyJWT valida firma (JWKS), iss, aud, exp, nbf, iat y nonce.
Multi-tenant listo: el tenant del token debe estar en `settings.tenants` y el issuer debe corresponder a ese tid.
"""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt

from app.shared.config import Settings
from app.shared.exceptions import UnauthorizedError
from app.shared.security import same

SCOPES = "openid profile email"
INVALID = "No fue posible validar la identidad de Microsoft"


def _post_form(url: str, data: dict) -> dict:
    req = Request(url, data=urlencode(data).encode(), headers={"Content-Type": "application/x-www-form-urlencoded",
                                                                 "Accept": "application/json"})
    try:
        with urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except HTTPError as e:  # 400 de Entra: código inválido/expirado/reutilizado
        try:
            return json.load(e)
        except ValueError:
            return {"error": f"http_{e.code}"}
    except (URLError, TimeoutError):
        return {"error": "unreachable"}


class EntraOidcClient:
    def __init__(self, cfg: Settings, http_post=_post_form, jwks_client=None):
        self.cfg = cfg
        self.authority = (cfg.microsoft_authority or "").rstrip("/")
        self._post = http_post
        self._jwks = jwks_client or jwt.PyJWKClient(f"{self.authority}/discovery/v2.0/keys", cache_keys=True,
                                                    lifespan=3600, timeout=15)

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        return f"{self.authority}/oauth2/v2.0/authorize?" + urlencode({
            "client_id": self.cfg.microsoft_client_id, "response_type": "code", "response_mode": "query",
            "redirect_uri": self.cfg.microsoft_redirect_uri, "scope": SCOPES, "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        })

    def exchange_code(self, code: str, code_verifier: str) -> str:
        data = self._post(f"{self.authority}/oauth2/v2.0/token", {
            "client_id": self.cfg.microsoft_client_id, "client_secret": self.cfg.microsoft_client_secret,
            "grant_type": "authorization_code", "code": code, "redirect_uri": self.cfg.microsoft_redirect_uri,
            "code_verifier": code_verifier, "scope": SCOPES,
        })
        if "id_token" not in data:
            raise UnauthorizedError(INVALID)
        return data["id_token"]

    def validate_id_token(self, id_token: str, nonce: str) -> dict:
        try:
            key = self._jwks.get_signing_key_from_jwt(id_token).key
            claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=self.cfg.microsoft_client_id,
                                leeway=60, options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]})
        except jwt.PyJWTError:
            raise UnauthorizedError(INVALID)
        tid = claims.get("tid")
        if (tid not in self.cfg.tenants or claims.get("iss") != f"https://login.microsoftonline.com/{tid}/v2.0"
                or not claims.get("oid") or not same(str(claims.get("nonce", "")), nonce)):
            raise UnauthorizedError(INVALID)
        return claims

    def logout_url(self) -> str | None:
        target = self.cfg.microsoft_post_logout_redirect_uri
        return f"{self.authority}/oauth2/v2.0/logout?" + urlencode({"post_logout_redirect_uri": target}) \
            if target else f"{self.authority}/oauth2/v2.0/logout"

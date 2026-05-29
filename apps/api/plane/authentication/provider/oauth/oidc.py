# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import pytz

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)


class OIDCOAuthProvider(OauthAdapter):
    """Generic OpenID Connect provider.

    Works against any standards-compliant, in-boundary identity provider
    (Keycloak, ADFS, Okta, Ping, Azure AD, etc.). Endpoints are configured
    explicitly rather than via discovery so the flow stays fully deterministic
    and makes no extra outbound call inside an air-gapped boundary.

    Configuration (instance config or environment):
      - OIDC_CLIENT_ID
      - OIDC_CLIENT_SECRET
      - OIDC_AUTHORIZATION_URL  (IdP authorize endpoint)
      - OIDC_TOKEN_URL          (IdP token endpoint)
      - OIDC_USERINFO_URL       (IdP userinfo endpoint)
    """

    provider = "oidc"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_AUTHORIZATION_URL,
            OIDC_TOKEN_URL,
            OIDC_USERINFO_URL,
        ) = get_configuration_value(
            [
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_AUTHORIZATION_URL",
                    "default": os.environ.get("OIDC_AUTHORIZATION_URL"),
                },
                {
                    "key": "OIDC_TOKEN_URL",
                    "default": os.environ.get("OIDC_TOKEN_URL"),
                },
                {
                    "key": "OIDC_USERINFO_URL",
                    "default": os.environ.get("OIDC_USERINFO_URL"),
                },
            ]
        )

        if not (
            OIDC_CLIENT_ID
            and OIDC_CLIENT_SECRET
            and OIDC_AUTHORIZATION_URL
            and OIDC_TOKEN_URL
            and OIDC_USERINFO_URL
        ):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        # Enforce a valid http(s) scheme on each endpoint to avoid SSRF-style
        # misconfiguration; do not leak details into query params on failure.
        for endpoint in (OIDC_AUTHORIZATION_URL, OIDC_TOKEN_URL, OIDC_USERINFO_URL):
            parsed = urlparse(endpoint)
            if parsed.scheme not in ("https", "http") or not parsed.netloc:
                raise AuthenticationException(
                    error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                    error_message="OIDC_NOT_CONFIGURED",
                )

        self.token_url = OIDC_TOKEN_URL
        self.userinfo_url = OIDC_USERINFO_URL

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET

        redirect_uri = f"{'https' if request.is_secure() else 'http'}://{request.get_host()}/auth/oidc/callback/"
        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{OIDC_AUTHORIZATION_URL}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {"Accept": "application/json"}
        token_response = self.get_user_token(data=data, headers=headers)
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("refresh_expires_in"))
                    if token_response.get("refresh_expires_in")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        # OIDC standard claims. "sub" is the stable, required subject identifier.
        email = user_info_response.get("email")
        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": str(user_info_response.get("sub")),
                    "email": email,
                    "avatar": user_info_response.get("picture", ""),
                    "first_name": (
                        user_info_response.get("given_name")
                        or user_info_response.get("name")
                        or user_info_response.get("preferred_username")
                        or ""
                    ),
                    "last_name": user_info_response.get("family_name", ""),
                    "is_password_autoset": True,
                },
            }
        )

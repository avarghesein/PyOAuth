from typing import Any, Dict, Optional, Callable
from pytest_mock import MockerFixture


from PyOAuthClient.Models.OAuthModels import OAuthProviderMetadata


class MockResponse:
    def __init__(
        self, json: Optional[Dict[str, Any]], text: Optional[str], status: int
    ) -> None:
        self._json = json
        self._text = text or str(json)
        self.text = self._text
        self.status = status
        self.status_code = status

    def json(self):
        return self._json

    def text1(self):
        return self._text

    def __aenter__(self):
        return self

    def __aexit__(self, exc_type, exc_value, traceback):
        pass


def mockHttp(
    mocker: MockerFixture,
    method: str,
    json: Optional[Dict[str, Any]],
    text: Optional[str],
    status=200,
):
    mocker.patch(
        f"httpx.Client.{method}",
        return_value=MockResponse(json=json, text=text, status=status),
    )

mockProviderMetadata = OAuthProviderMetadata(
    issuer="https://logto.app",
    authorization_endpoint="https://logto.app/oidc/auth",
    token_endpoint="https://logto.app/oidc/auth/token",
    userinfo_endpoint="https://logto.app/oidc/userinfo",
    jwks_uri="https://logto.app/oidc/jwks",
    response_types_supported=[],
    subject_types_supported=[],
    id_token_signing_alg_values_supported=[],
    userlist_endpoint="https://logto.app/api"
)
    


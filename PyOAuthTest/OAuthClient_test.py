from typing import Any, Callable, Dict, Optional
from pytest_mock import MockerFixture
import pytest

from . import removeFalsyKeys, urlsafeEncode

from PyOAuthClient import OAuthClient, OAuthConfig, OAuthException, Storage
from PyOAuthClient.Models.OAuthResponse import TokenResponse, UserInfoResponse
from PyOAuthClient.Models.OAuthModels import IdTokenClaims, AccessTokenClaims, UserInfoScope
from PyOAuthClient.Storage import MemoryStorage, Storage
from PyOAuthClient.OAuthCore import OAuthCore

from PyOAuthTest.test import mockHttp, mockProviderMetadata

MockRequest = Callable[..., None]


class TestOAuthClient:
    @pytest.fixture
    def config(self) -> OAuthConfig:
        return OAuthConfig(
            endpoint="http://localhost:3001",  # Replace with your OAuth endpoint
            appId="replace-with-your-app-id",
        )

    @pytest.fixture
    def mockRequest(self, mocker: MockerFixture) -> MockRequest:
        def _mock(
            method: str = "get",
            json: Optional[Dict[str, Any]] = None,
            text: Optional[str] = None,
            status: int = 200,
        ):
            return mockHttp(mocker, method, json, text, status)

        return _mock

    @pytest.fixture
    def storage(self) -> Storage:
        return MemoryStorage()

    @pytest.fixture
    def client(
        self,
        config: OAuthConfig,
        storage: Storage,
        mockRequest: MockRequest,
        mocker: MockerFixture,
    ) -> OAuthClient:
        mocker.patch(
            "PyOAuthClient.OAuthCore.OAuthCore.generateCodeVerifier", return_value="codeVerifier"
        )
        mocker.patch(
            "PyOAuthClient.OAuthCore.OAuthCore.generateCodeChallenge",
            return_value="codeChallenge",
        )
        mocker.patch("PyOAuthClient.OAuthCore.OAuthCore.generateState", return_value="state")
        mockRequest(json=mockProviderMetadata.__dict__)
        return OAuthClient(config, storage)

    async def test_getOidcCore(self, client: OAuthClient) -> None:
        assert isinstance(await client.getOidcCore(), OAuthCore)

    async def test_signIn(self, client: OAuthClient) -> None:
        url = await client.signIn("redirectUri", "signUp")

        assert (
            url
            == "https://logto.app/oidc/auth?client_id=replace-with-your-app-id&redirect_uri=redirectUri&response_type=code&scope=openid+offline_access+profile&prompt=consent&code_challenge=codeChallenge&code_challenge_method=S256&state=state&interaction_mode=signUp"
        )

    async def test_signIn_multipleResources(self, client: OAuthClient) -> None:
        client.config.resources = ["https://resource1", "https://resource2"]
        url = await client.signIn("redirectUri", "signUp")

        assert (
            url
            == "https://logto.app/oidc/auth?client_id=replace-with-your-app-id&redirect_uri=redirectUri&response_type=code&scope=openid+offline_access+profile&resource=https%3A%2F%2Fresource1&resource=https%3A%2F%2Fresource2&prompt=consent&code_challenge=codeChallenge&code_challenge_method=S256&state=state&interaction_mode=signUp"
        )

    async def test_signIn_multipleScopes(self, client: OAuthClient) -> None:
        client.config.scopes = [UserInfoScope.email, "phone"]
        url = await client.signIn("redirectUri")

        assert (
            url
            == "https://logto.app/oidc/auth?client_id=replace-with-your-app-id&redirect_uri=redirectUri&response_type=code&scope=email+phone+openid+offline_access+profile&prompt=consent&code_challenge=codeChallenge&code_challenge_method=S256&state=state"
        )

    async def test_signIn_allConfigs(self, client: OAuthClient) -> None:
        client.config.scopes = ["email", "phone"]
        client.config.resources = ["https://resource1", "https://resource2"]
        client.config.prompt = "login"
        url = await client.signIn("redirectUri", "signUp")

        assert (
            url
            == "https://logto.app/oidc/auth?client_id=replace-with-your-app-id&redirect_uri=redirectUri&response_type=code&scope=email+phone+openid+offline_access+profile&resource=https%3A%2F%2Fresource1&resource=https%3A%2F%2Fresource2&prompt=login&code_challenge=codeChallenge&code_challenge_method=S256&state=state&interaction_mode=signUp"
        )

    async def test_signOut(
        self, client: OAuthClient, storage: Storage, mockRequest: MockRequest
    ) -> None:
        # Add end session endpoint to metadata
        mockRequest(
            method="get",
            json={
                **mockProviderMetadata.__dict__,
                "end_session_endpoint": "https://logto.app/oidc/logout",
            },
        )

        storage.set("idToken", "idToken")
        storage.set("accessTokenMap", "accessTokenMap")
        storage.set("refreshToken", "refreshToken")

        url = await client.signOut("redirectUri")

        assert (
            url
            == "https://logto.app/oidc/logout?client_id=replace-with-your-app-id&post_logout_redirect_uri=redirectUri"
        )

        assert storage.get("idToken") is None
        assert storage.get("accessTokenMap") is None
        assert storage.get("refreshToken") is None

    async def test_signOut_failure(self, client: OAuthClient) -> None:
        with pytest.raises(
            OAuthException,
            match="End session endpoint not found in the provider metadata",
        ):
            await client.signOut("redirectUri")

    async def test_handleSignInCallback_sessionNotFound(
        self,
        client: OAuthClient,
    ) -> None:
        with pytest.raises(OAuthException, match="Sign-in session not found"):
            await client.handleSignInCallback(callbackUri="https://redirect_uri")

    async def test_handleSignInCallback_pathDoesNotMatch(
        self, client: OAuthClient, storage: Storage
    ) -> None:
        storage.set(
            "signInSession",
            '{"redirectUri": "https://redirect_uri/some_path", "codeVerifier": "codeVerifier", "state": "state"}',
        )
        with pytest.raises(
            OAuthException,
            match="The URI path does not match the redirect URI in the sign-in session",
        ):
            await client.handleSignInCallback(callbackUri="https://redirect_uri")

    async def test_handleSignInCallback_stateDoesNotMatch(
        self, client: OAuthClient, storage: Storage
    ) -> None:
        storage.set(
            "signInSession",
            '{"redirectUri": "https://redirect_uri", "codeVerifier": "codeVerifier", "state": "state"}',
        )
        with pytest.raises(
            OAuthException,
            match="Invalid state in the callback URI",
        ):
            await client.handleSignInCallback(
                callbackUri="https://redirect_uri?state=state2"
            )

    async def test_handleSignInCallback_codeNotFound(
        self, client: OAuthClient, storage: Storage
    ) -> None:
        storage.set(
            "signInSession",
            '{"redirectUri": "https://redirect_uri", "codeVerifier": "codeVerifier", "state": "state"}',
        )
        with pytest.raises(OAuthException, match="Code not found in the callback URI"):
            await client.handleSignInCallback(
                callbackUri="https://redirect_uri?state=state"
            )

    async def test_handleSignInCallback(
        self,
        client: OAuthClient,
        storage: Storage,
        mockRequest: MockRequest,
        mocker: MockerFixture,
    ) -> None:
        storage.set(
            "signInSession",
            '{"redirectUri": "https://redirect_uri", "codeVerifier": "codeVerifier", "state": "state"}',
        )

        # Mock getOidcCore()
        client.getOidcCore = mocker.AsyncMock(
            return_value=OAuthCore(mockProviderMetadata),
        )

        # Mock token response
        tokenResponse = TokenResponse(
            access_token="accessToken",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refreshToken",
            id_token="idToken",
            status_code=200
        )

        mockRequest(method="post", json=tokenResponse.__dict__)

        # Mock verifyIdToken()
        mocker.patch("PyOAuthClient.OAuthCore.OAuthCore.verifyIdToken", return_value=None)

        # Should not raise
        await client.handleSignInCallback(
            callbackUri="https://redirect_uri?state=state&code=code"
        )

        assert storage.get("idToken") == "idToken"
        assert storage.get("refreshToken") == "refreshToken"
        assert await client.getAccessToken("") == "accessToken"

    async def test_getAccessToken_cached(
        self,
        client: OAuthClient,
        storage: Storage,
    ) -> None:
        assert await client.getAccessToken("") == None
        storage.set(
            "accessTokenMap",
            '{"x":{"":{"token":"access_token","expiresAt": 9999999999}, "foo":{"token":"access_token_foo","expiresAt": 9999999999}}}',
        )
        assert await client.getAccessToken("") == "access_token"
        assert await client.getAccessToken(resource="foo") == "access_token_foo"

    async def test_getAccessToken_noRefreshToken(
        self,
        client: OAuthClient,
        storage: Storage,
    ) -> None:
        storage.set("accessTokenMap", '{"x":{}}')
        storage.set("refreshToken", None)
        assert await client.getAccessToken("") == None

    async def test_getAccessToken_useRefreshToken(
        self,
        client: OAuthClient,
        storage: Storage,
        mockRequest: MockRequest,
    ) -> None:
        storage.set("accessTokenMap", '{"x":{}}')
        storage.set("refreshToken", "refreshToken")

        # Mock token response
        tokenResponse = TokenResponse(
            access_token="accessToken",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refreshToken",
            status_code=200
        )
        mockRequest(method="post", json=tokenResponse.__dict__)

        assert await client.getAccessToken("") == "accessToken"

    async def test_getAccessTokenClaims(
        self, client: OAuthClient, storage: Storage
    ) -> None:
        # Assign a valid access token raw string
        accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2xvZ3RvLmFwcCIsImF1ZCI6Imh0dHBzOi8vbG9ndG8uYXBwL2FwaSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjE2NDQ2MzAwLCJzdWIiOiJ1c2VyMSIsInNjb3BlIjoiYWRtaW4gdXNlciIsImNsaWVudF9pZCI6InNhcXJlMW9xYmtwajZ6aHE4NWhvMCJ9.12345678901234567890123456789012345678901234567890"
        storage.set(
            "accessTokenMap",
            '{"x":{"":{"token":"' + accessToken + '", "expiresAt": 9999999999}}}',
        )

        assert await client.getAccessTokenClaims() == AccessTokenClaims(
            iss="https://logto.app",
            aud="https://logto.app/api",
            exp=9999999999,
            iat=1616446300,
            sub="user1",
            scope="admin user",
            client_id="saqre1oqbkpj6zhq85ho0",
        )

    async def test_getIdToken(
        self,
        client: OAuthClient,
        storage: Storage,
    ) -> None:
        assert client.getIdToken() == None
        storage.set("idToken", "idToken")
        assert client.getIdToken() == "idToken"

    async def test_getIdTokenClaims(
        self, client: OAuthClient, storage: Storage
    ) -> None:
        idTokenString = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2xvZ3RvLmFwcCIsImF1ZCI6ImZvbyIsImV4cCI6MTYxNjQ0NjQwMCwiaWF0IjoxNjE2NDQ2MzAwLCJzdWIiOiJ1c2VyMSIsIm5hbWUiOiJKb2huIFdpY2siLCJ1c2VybmFtZSI6ImpvaG4iLCJlbWFpbCI6ImpvaG5Ad2ljay5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.12345678901234567890123456789012345678901234567890"
        storage.set("idToken", idTokenString)
        assert client.getIdTokenClaims() == IdTokenClaims(
            iss="https://logto.app",
            aud="foo",
            exp=1616446400,
            iat=1616446300,
            sub="user1",
            name="John Wick",
            username="john",
            email="john@wick.com",
            email_verified=True,
        )

    async def test_getRefreshToken(
        self,
        client: OAuthClient,
        storage: Storage,
    ) -> None:
        assert client.getRefreshToken() == None
        storage.set("refreshToken", "refreshToken")
        assert client.getRefreshToken() == "refreshToken"

    async def test_isAuthenticated(
        self,
        client: OAuthClient,
        storage: Storage,
    ) -> None:
        assert client.isAuthenticated() == False
        storage.set("idToken", "idToken")
        assert client.isAuthenticated() == True

    async def test_fetchUserInfo(
        self, client: OAuthClient, mocker: MockerFixture
    ) -> None:
        userinfoResponse = UserInfoResponse(
            sub="user1", name="John Wick", username="john", email="john@wick.com"
        )

        async def mockFetchUserInfo(accessToken: str) -> UserInfoResponse:
            return userinfoResponse

        client.getAccessToken = mocker.AsyncMock(return_value="accessToken")
        mocker.patch(
            "PyOAuthClient.OAuthCore.OAuthCore.fetchUserInfo",
            side_effect=mockFetchUserInfo,
        )

        assert await client.fetchUserInfo() == userinfoResponse

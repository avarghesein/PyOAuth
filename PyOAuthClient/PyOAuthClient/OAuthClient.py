"""OAuthClientWrapper"""

from typing import Dict, Literal, Optional
import time
from typing import Dict, List, Literal, Optional, Union
from pydantic import BaseModel
import urllib.parse

from PyOAuthClient.Models.OAuthModels import Scope

from PyOAuthClient.Storage import MemoryStorage, Storage
from PyOAuthClient.OAuthException import OAuthException
from PyOAuthClient.OAuthCore import (
    AccessTokenClaims,
    IdTokenClaims,
    OAuthCore,
    TokenResponse,
    UserInfoResponse,
)
from PyOAuthClient import removeFalsyKeys


class OAuthConfig(BaseModel):
    """
    The configuration object for the OAuth Client.
    """

    wellKnownMetaDataEndpoint: str
    endpoint: str
    """
    The endpoint for the OAuth Server, you can get it from the integration guide
    or the team settings page of the OAuth console.

    Example:
    https://foo.logto.app
    """

    appId: str
    """
    The client ID of your application, you can get it from the integration guide
    or the application details page of the OAuth console.
    """

    appSecret: Optional[str] = None
    """
    The client secret of your application, you can get it from the integration guide
    or the application details page of the OAuth console.
    """

    prompt: Literal["consent", "login"] = "consent"
    """
    The prompt parameter for the OpenID Connect authorization request.

    - If the value is `consent`, the user will be able to reuse the existing consent
    without being prompted for sign-in again.
    - If the value is `login`, the user will be prompted for sign-in again anyway. Note
    there will be no Refresh Token returned in this case.
    """

    resources: List[str] = []
    """
    The API resources that your application needs to access. You can specify multiple
    resources by providing an array of strings.

    See https://docs.logto.io/docs/recipes/rbac/ to learn more about how to use role-based
    access control (RBAC) to protect API resources.
    """

    scopes: List[Union[str, Scope]] = []
    """
    The scopes (permissions) that your application needs to access.
    Scopes that will be added by default: `openid`, `offline_access` and `profile`.

    If resources are specified, scopes will be applied to every resource.

    See https://docs.logto.io/docs/recipes/integrate-logto/vanilla-js/#fetch-user-information
    for more information of available scopes for user information.
    """


class SignInSession(BaseModel):
    """
    The sign-in session that stores the information for the sign-in callback.
    Should be stored before redirecting the user to OAuth.
    """

    redirectUri: str
    """
    The redirect URI for the current sign-in session.
    """
    codeVerifier: str
    """
    The code verifier of Proof Key for Code Exchange (PKCE).
    """
    state: str
    """
    The state for OAuth 2.0 authorization request.
    """


class AccessToken(BaseModel):
    """
    The access token class for a resource.
    """

    token: str
    """
    The access token string.
    """
    expiresAt: int
    """
    The timestamp (in seconds) when the access token will expire.
    Note this is not the expiration time of the access token itself, but the
    expiration time of the access token cache.
    """


class AccessTokenMap(BaseModel):
    """
    The access token map that maps the resource to the access token for that resource.

    If resource is an empty string, it means the access token is for UserInfo endpoint
    or the default resource.
    """

    x: Dict[str, AccessToken]


InteractionMode = Literal["signIn", "signUp"]
"""
The interaction mode for the sign-in request. Note this is not a part of the OIDC
specification, but a logto extension.
"""


class OAuthClient:
    """
    The main class of the OAuth Client. You should create an instance of this class
    and use it to sign in, sign out, get access token, etc.
    """

    def __init__(self, config: OAuthConfig, storage: Storage = MemoryStorage()) -> None:
        self.config = config
        self._oidcCore: Optional[OAuthCore] = None
        self._storage = storage

    async def getOidcCore(self) -> OAuthCore:
        """
        Get the OIDC core object. You can use it to get the provider metadata, verify
        the ID token, fetch tokens by code or refresh token, etc.
        """

        if self.config.wellKnownMetaDataEndpoint:
            metadata = await OAuthCore.getProviderMetadata(f"{self.config.wellKnownMetaDataEndpoint}")
        else:    
            metadata = await OAuthCore.getProviderMetadata(f"{self.config.endpoint}/oidc/.well-known/openid-configuration")

        metadata.userlist_endpoint = self.config.endpoint + "/api/users"

        if self._oidcCore is None:
            self._oidcCore = OAuthCore(metadata)

        return self._oidcCore

    def _getAccessTokenMap(self, callerArgs: dict = {}) -> AccessTokenMap:
        """
        Get the access token map from storage.
        """
        accessTokenMap = self._storage.get("accessTokenMap", callerArgs)
        try:
            return AccessTokenMap.model_validate_json(accessTokenMap)
        except:
            return AccessTokenMap(x={})

    def SetAccessTokenForExternalCallers(self, accessToken: str, resource: str = "", expiresIn: int = 86400, callerArgs: dict = {}) -> None:
        self._setAccessToken(resource, accessToken, expiresIn, callerArgs)

    def _setAccessToken(self, resource: str, accessToken: str, expiresIn: int, callerArgs: dict = {}) -> None:
        """
        Set the access token for the given resource to storage.
        """
        accessTokenMap = self._getAccessTokenMap(callerArgs)
        accessTokenMap.x[resource] = AccessToken(
            token=accessToken,
            expiresAt=int(time.time())
            + expiresIn
            - 60,  # 60 seconds earlier to avoid clock skew
        )
        self._storage.set("accessTokenMap", accessTokenMap.model_dump_json(), callerArgs)

    def _getAccessToken(self, resource: str, callerArgs: dict = {}) -> Optional[str]:
        """
        Get the valid access token for the given resource from storage, no refresh will be
        performed.
        """
        accessTokenMap = self._getAccessTokenMap(callerArgs)
        accessToken = accessTokenMap.x.get(resource, None)
        if accessToken is None or accessToken.expiresAt < int(time.time()):
            return None
        return accessToken.token

    async def _handleTokenResponse(
        self, resource: str, tokenResponse: TokenResponse, callerArgs: dict = {}
    ) -> None:
        """
        Handle the token response from the OAuth Server and store the tokens to storage.

        Resource can be an empty string, which means the access token is for UserInfo
        endpoint or the default resource.
        """
        if tokenResponse.id_token is not None:
            (await self.getOidcCore()).verifyIdToken(
                tokenResponse.id_token, self.config.appId
            )
            self._storage.set("idToken", tokenResponse.id_token, callerArgs)

        if tokenResponse.refresh_token is not None:
            self._storage.set("refreshToken", tokenResponse.refresh_token, callerArgs)

        self._setAccessToken(
            resource, tokenResponse.access_token, tokenResponse.expires_in, callerArgs
        )

    async def _buildSignInUrl(
        self,
        redirectUri: str,
        codeChallenge: str,
        state: str,
        interactionMode: Optional[InteractionMode] = None, callerArgs: dict = {}
    ) -> str:
        appId, prompt, resources, scopes = (
            self.config.appId,
            self.config.prompt,
            self.config.resources,
            self.config.scopes,
        )
        authorizationEndpoint = (
            await self.getOidcCore()
        ).metadata.authorization_endpoint

        params = {
                    "client_id": appId,
                    "redirect_uri": redirectUri,
                    "response_type": "code",
                    "scope": " ".join(
                        (item.value if isinstance(item, Scope) else item)
                        for item in (scopes + OAuthCore.defaultScopes)
                    ),
                    "prompt": prompt,
                    "code_challenge": codeChallenge,
                    "code_challenge_method": "S256",
                    "state": state,
                    "interaction_mode": interactionMode,
                }
        
        resources = [res for res in resources if res != None and res.strip() != ""]

        if len(resources) > 0:
            print("Including resources in SignIn Url " + str(resources))
            params["resource"] = resources
        else:
            print("Exluding resources")

        query = urllib.parse.urlencode(
            removeFalsyKeys(params),
            True,
        )

        return f"{authorizationEndpoint}?{query}"

    def _getSignInSession(self, callerArgs: dict = {}) -> Optional[SignInSession]:
        """
        Try to parse the current sign-in session from storage. If the value does not
        exist or parse failed, return None.
        """
        signInSession = self._storage.get("signInSession", callerArgs)
        if signInSession is None:
            return None
        try:
            return SignInSession.model_validate_json(signInSession)
        except:
            return None

    def _setSignInSession(self, signInSession: SignInSession, callerArgs: dict = {}) -> None:
        self._storage.set("signInSession", signInSession.model_dump_json(), callerArgs)

    async def signIn(
        self, redirectUri: str, interactionMode: Optional[InteractionMode] = None, callerArgs: dict = {}
    ) -> str:
        """
        Returns the sign-in URL for the given redirect URI. You should redirect the user
        to the returned URL to sign in.

        By specifying the interaction mode, you can control whether the user will be
        prompted for sign-in or sign-up on the first screen. If the interaction mode is
        not specified, the default one will be used.

        Example:
          ```python
          return redirect(await client.signIn('https://example.com/callback'))
          ```
        """
        codeVerifier = OAuthCore.generateCodeVerifier()
        codeChallenge = OAuthCore.generateCodeChallenge(codeVerifier)
        state = OAuthCore.generateState()
        signInUrl = await self._buildSignInUrl(
            redirectUri, codeChallenge, state, interactionMode, callerArgs
        )

        self._setSignInSession(
            SignInSession(
                redirectUri=redirectUri,
                codeVerifier=codeVerifier,
                state=state
            ),callerArgs
        )
        for key in ["idToken", "accessToken", "refreshToken"]:
            self._storage.delete(key, callerArgs)

        return signInUrl

    async def signOut(self, postLogoutRedirectUri: Optional[str] = None, callerArgs: dict = {}) -> str:
        """
        Returns the sign-out URL for the given post-logout redirect URI. You should
        redirect the user to the returned URL to sign out.

        If the post-logout redirect URI is not provided, the OAuth default post-logout
        redirect URI will be used.

        Note:
          If the OpenID Connect server does not support the end session endpoint
          (i.e. OpenID Connect RP-Initiated Logout), the function will throw an
          exception. OAuth supports the end session endpoint.

        Example:
          ```python
          return redirect(await client.signOut('https://example.com'))
          ```
        """
        self._storage.delete("idToken", callerArgs)
        self._storage.delete("refreshToken", callerArgs)
        self._storage.delete("accessTokenMap", callerArgs)

        endSessionEndpoint = (await self.getOidcCore()).metadata.end_session_endpoint

        if endSessionEndpoint is None:
            raise OAuthException(
                "End session endpoint not found in the provider metadata"
            )

        return (
            endSessionEndpoint
            + "?"
            + urllib.parse.urlencode(
                removeFalsyKeys(
                    {
                        "client_id": self.config.appId,
                        "post_logout_redirect_uri": postLogoutRedirectUri,
                    }
                )
            )
        )

    async def handleSignInCallback(self, callbackUri: str, callerArgs: dict = {}) -> None:
        """
        Handle the sign-in callback from the OAuth Server. This method should be called
        in the callback route handler of your application.
        """
        signInSession = self._getSignInSession( callerArgs)

        if signInSession is None:
            raise OAuthException("Sign-in session not found")

        # Validate the callback URI without query matches the redirect URI
        parsedCallbackUri = urllib.parse.urlparse(callbackUri)

        if (
            parsedCallbackUri.path
            != urllib.parse.urlparse(signInSession.redirectUri).path
        ):
            raise OAuthException(
                "The URI path does not match the redirect URI in the sign-in session"
            )

        query = urllib.parse.parse_qs(parsedCallbackUri.query)

        if "error" in query:
            raise OAuthException(query["error"][0])

        if signInSession.state != query.get("state", [None])[0]:
            raise OAuthException("Invalid state in the callback URI")

        code = query.get("code", [None])[0]
        if code is None:
            raise OAuthException("Code not found in the callback URI")

        tokenResponse = await (await self.getOidcCore()).fetchTokenByCode(
            clientId=self.config.appId,
            clientSecret=self.config.appSecret,
            redirectUri=signInSession.redirectUri,
            code=code,
            codeVerifier=signInSession.codeVerifier,
        )

        await self._handleTokenResponse("", tokenResponse, callerArgs)
        self._storage.delete("signInSession", callerArgs)

    async def getAdminAccessToken(self, resource: str, callerArgs: dict = {}) -> Optional[str]:
            """
            Get the access token for the given resource. If the access token is expired,
            it will be refreshed automatically. If no refresh token is found, None will
            be returned.
            """
            accessToken = self._getAccessToken(resource, callerArgs)
            if accessToken is not None:
                return accessToken

            tokenResponse = await (await self.getOidcCore()).fetchAdminToken(
                clientId=self.config.appId,
                clientSecret=self.config.appSecret,
                resourceUri=resource,
                scope=" ".join(
                        (item.value if isinstance(item, Scope) else item)
                        for item in (self.config.scopes)
                    )
            )

            await self._handleTokenResponse(resource, tokenResponse, callerArgs)
            return tokenResponse.access_token

    async def getAccessToken(self, resource: str, callerArgs: dict = {}) -> Optional[str]:
        """
        Get the access token for the given resource. If the access token is expired,
        it will be refreshed automatically. If no refresh token is found, None will
        be returned.
        """
        accessToken = self._getAccessToken(resource, callerArgs)
        if accessToken is not None:
            return accessToken

        refreshToken = self._storage.get("refreshToken", callerArgs)
        if refreshToken is None:
            return None

        tokenResponse = await (await self.getOidcCore()).fetchTokenByRefreshToken(
            clientId=self.config.appId,
            clientSecret=self.config.appSecret,
            refreshToken=refreshToken,
            resource=resource
        )

        await self._handleTokenResponse(resource, tokenResponse, callerArgs)
        return tokenResponse.access_token

    async def getAccessTokenClaims(self, resource: str = "", callerArgs: dict = {}) -> AccessTokenClaims:
        """
        Get the claims in the access token for the given resource. If the access token
        is expired, it will be refreshed automatically. If it's unable to refresh the
        access token, an exception will be thrown.
        """
        accessToken = await self.getAccessToken(resource, callerArgs)
        return OAuthCore.decodeAccessToken(accessToken)

    def getIdToken(self, callerArgs: dict = {}) -> Optional[str]:
        """
        Get the ID Token string. If you need to get the claims in the ID Token, use
        `getIdTokenClaims` instead.
        """
        return self._storage.get("idToken", callerArgs)

    def getIdTokenClaims(self, callerArgs: dict = {}) -> IdTokenClaims:
        """
        Get the claims in the ID Token. If the ID Token does not exist, an exception
        will be thrown.
        """
        idToken = self._storage.get("idToken", callerArgs)
        if idToken is None:
            raise OAuthException("ID Token not found")

        return OAuthCore.decodeIdToken(idToken)

    def getRefreshToken(self, callerArgs: dict = {}) -> Optional[str]:
        """
        Get the refresh token string.
        """
        return self._storage.get("refreshToken", callerArgs)

    def isAuthenticated(self, callerArgs: dict = {}) -> bool:
        """
        Check if the user is authenticated by checking if the ID Token exists.
        """
        return self._storage.get("idToken", callerArgs) is not None

    async def IsAccessTokenValid(self, callerArgs: dict = {}):
        try:
            userInfo = await self.fetchUserInfo(callerArgs)
            return True, userInfo
        except Exception as eX:
            return False, str(eX)
    
    
    async def fetchUserInfo(self, callerArgs: dict = {}) -> UserInfoResponse:
        """
        Fetch the user information from the UserInfo endpoint. If the access token
        is expired, it will be refreshed automatically.
        """
        accessToken = await self.getAccessToken("", callerArgs)
        return await (await self.getOidcCore()).fetchUserInfo(accessToken)

    """Fetch the Users from the OAuth Server through Management API"""
    async def fetchUserList(self,resource: str = "", callerArgs: dict = {}):
        """
        Fetch the user information from the UserInfo endpoint. If the access token
        is expired, it will be refreshed automatically.
        """
        accessToken = await self.getAdminAccessToken(resource, callerArgs)
        return await (await self.getOidcCore()).fetchUserList(accessToken)
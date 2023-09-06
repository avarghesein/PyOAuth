"""
The core OIDC functions for the OAuth client. Provider-agonistic functions
are implemented as static methods, while other functions are implemented as
instance methods.
"""

import hashlib
import secrets
from jwt import PyJWKClient
import jwt
from typing import List, Optional
import httpx

from PyOAuthClient.OAuthException import OAuthException
from PyOAuthClient.Models.OAuthModels import (
    AccessTokenClaims,
    IdTokenClaims,
    OAuthScope,
    OAuthProviderMetadata,
    Scope,
    UserInfoScope,
)
from PyOAuthClient.Models.OAuthResponse import TokenResponse, UserInfoResponse
from PyOAuthClient import removeFalsyKeys, urlsafeEncode


class OAuthCore:
    defaultScopes: List[Scope] = [
        UserInfoScope.openid,
        OAuthScope.offlineAccess,
        UserInfoScope.profile,
    ]

    def __init__(self, metadata: OAuthProviderMetadata) -> None:
        """
        Initialize the OIDC core with the provider metadata. You can use the
        `getProviderMetadata` method to fetch the provider metadata from the
        discovery URL.
        """
        self.metadata = metadata

        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        self.jwksClient = PyJWKClient(
            metadata.jwks_uri, headers={"user-agent": "@logto/python", "accept": "*/*"}, ssl_context=ctx
        )

    def generateState() -> str:
        """
        Generate a random string (32 bytes) for the state parameter.
        """
        return urlsafeEncode(secrets.token_bytes(32))

    def generateCodeVerifier() -> str:
        """
        Generate a random code verifier string (32 bytes) for PKCE.

        See: https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1
        """
        return urlsafeEncode(secrets.token_bytes(32))

    def generateCodeChallenge(codeVerifier: str) -> str:
        """
        Generate a code challenge string for the given code verifier string.

        See: https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
        """
        return urlsafeEncode(hashlib.sha256(codeVerifier.encode("ascii")).digest())

    def decodeIdToken(idToken: str) -> IdTokenClaims:
        """
        Decode the ID Token and return the claims without verifying the signature.
        """
        return IdTokenClaims(**jwt.decode(idToken, options={"verify_signature": False}))

    def decodeAccessToken(accessToken: str) -> AccessTokenClaims:
        """
        Decode the access token and return the claims without verifying the signature.
        """
        return AccessTokenClaims(
            **jwt.decode(accessToken, options={"verify_signature": False})
        )

    async def getProviderMetadata(discoveryUrl: str) -> OAuthProviderMetadata:
        """
        Fetch the provider metadata from the discovery URL.
        """
        with httpx.Client(http2=True, verify=False) as client:
            resp = client.get(discoveryUrl)
            jsonData = resp.json()
            return OAuthProviderMetadata(**jsonData)

    async def fetchAdminToken(
            self,
            clientId: str,
            clientSecret: Optional[str],
            resourceUri: str,
            scope: str
        ) -> TokenResponse:
            """
            Fetch the token from the token endpoint using the authorization code.
            """
            tokenEndpoint = self.metadata.token_endpoint

            with httpx.Client(http2=True, verify=False) as session:
                response = session.post(tokenEndpoint, json={
                        "grant_type": "client_credentials",
                        "client_id": clientId,
                        "client_secret": clientSecret,
                        "resource": resourceUri,
                        'scope': scope
                    })
                
                if response.status_code != 200:
                    raise OAuthException(response.text)
                
                jsonData = response.json()
                return TokenResponse(**jsonData)
        
    async def fetchTokenByCode(
        self,
        clientId: str,
        clientSecret: Optional[str],
        redirectUri: str,
        code: str,
        codeVerifier: str,
    ) -> TokenResponse:
        """
        Fetch the token from the token endpoint using the authorization code.
        """
        tokenEndpoint = self.metadata.token_endpoint

        with httpx.Client(http2=True, verify=False) as session:
            response = session.post(tokenEndpoint, json={
                    "grant_type": "authorization_code",
                    "client_id": clientId,
                    "client_secret": clientSecret,
                    "redirect_uri": redirectUri,
                    "code": code,
                    "code_verifier": codeVerifier,
                })
            
            if response.status_code != 200:
                raise OAuthException(response.text)
            
            jsonData = response.json()
            return TokenResponse(**jsonData)

    async def fetchTokenByRefreshToken(
        self,
        clientId: str,
        clientSecret: Optional[str],
        refreshToken: str,
        resource: str = "",
    ) -> TokenResponse:
        """
        Fetch the token from the token endpoint using the refresh token.
        """
        tokenEndpoint = self.metadata.token_endpoint

        with httpx.Client(http2=True, verify=False) as session:
            response = session.post(tokenEndpoint, json=removeFalsyKeys(
                    {
                        "grant_type": "refresh_token",
                        "client_id": clientId,
                        "client_secret": clientSecret,
                        "refresh_token": refreshToken,
                        "resource": resource,
                    }))
            
            if response.status_code != 200:
                raise OAuthException(response.text)
            
            jsonData = response.json()
            return TokenResponse(**jsonData)
        
    def verifyIdToken(self, idToken: str, clientId: str) -> None:
        """
        Verify the ID Token signature and its issuer and client ID, throw an exception
        if the verification fails.
        """
        issuer = self.metadata.issuer

        jwksUri = self.metadata.jwks_uri

        with httpx.Client(http2=True, verify=False) as client:
            resp = client.get(jwksUri)
            if resp.status_code != 200:
                raise OAuthException(resp.text)
            jskey = resp.json()

        from jwcrypto import jwk
        import json
        jskey=jskey["keys"][0]

        key = jwk.JWK(**jskey)
        public_key=key.export_to_pem()
        print(public_key)

        jwt.decode(
            idToken,
            #signing_key.key,
            public_key,
            algorithms=["RS256", "PS256", "ES256", "ES384", "ES512"],
            audience=clientId,
            issuer=issuer,
            leeway=30,
            verify=False
        )

    async def fetchUserList(self, accessToken: str):
            """
            Fetch the user info from the OpenID Connect UserInfo endpoint.

            See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
            """
            userlistEndpoint = self.metadata.userlist_endpoint

            with httpx.Client(http2=True, verify=False) as client:
                resp = client.get(userlistEndpoint, headers={"Authorization": f"Bearer {accessToken}"})
                if resp.status_code != 200:
                    raise OAuthException(resp.text)
                jsonData = resp.json()
                return jsonData
        
    async def fetchUserInfo(self, accessToken: str) -> UserInfoResponse:
        """
        Fetch the user info from the OpenID Connect UserInfo endpoint.

        See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        """
        userInfoEndpoint = self.metadata.userinfo_endpoint

        with httpx.Client(http2=True, verify=False) as client:
            resp = client.get(userInfoEndpoint, headers={"Authorization": f"Bearer {accessToken}"})
            if resp.status_code != 200:
                raise OAuthException(resp.text)
            jsonData = resp.json()
            return UserInfoResponse(**jsonData)

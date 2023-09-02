import base64
from typing import Any, Dict


def urlsafeEncode(data: bytes) -> str:
    """
    Encode the given bytes to a URL-safe string.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def removeFalsyKeys(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove keys with falsy values from the given dictionary.
    """
    return {k: v for k, v in data.items() if v}


from PyOAuthClient.OAuthClient import (
    OAuthClient as OAuthClient,
    OAuthConfig as OAuthConfig,
    InteractionMode as InteractionMode,
    AccessToken as AccessToken,
)
from PyOAuthClient.OAuthException import OAuthException as OAuthException
from PyOAuthClient.Storage import Storage as Storage, PersistKey as PersistKey
from PyOAuthClient.Models.OAuthModels import (
    AccessTokenClaims as AccessTokenClaims,
    IdTokenClaims as IdTokenClaims,
    OAuthProviderMetadata as OAuthProviderMetadata,
    Scope as Scope,
    UserInfoScope as UserInfoScope,
)
from PyOAuthClient.Models.OAuthResponse import (
    TokenResponse as TokenResponse,
    UserInfoResponse as UserInfoResponse,
)

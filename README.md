# PyOAuth
## A Python OAuth / OpenID Client Library Supports
* Connecting to an OAuthServer serving with HTTP/2 Protocol
* Connecting to an OAuthServer having a Self Signed Certificate
* Connecting to the Management API endpoint of an OAuth Server, for administering Users/Other OAuth Server Resources

## How To Test
* Have Your OAuth Server Details Or [Self Host One](https://github.com/avarghesein/PyOAuth/blob/main/PyOAuthTest/SelfHostOAuthServer.md)
* Create a Python Virtual Environment and install the packages mentioned in ['requirements.txt'](https://github.com/avarghesein/PyOAuth/blob/main/PyOAuthTest/requirements.txt)
* Update your OAuth Server details in [DemoWebServer](https://github.com/avarghesein/PyOAuth/blob/main/PyOAuthTest/DemoWebServer.py)
* Run DemoWebServer

## Custom Argument Support, to Enable Sessions Similar to FastAPI

      @app.get("/signin")  
      async def sign_in(request: Request):
        callerArgs = { "session" : request.session }
        return RedirectResponse(
            await client.signIn(
                redirectUri= request.base_url._url + "signin_callback",
                interactionMode="signUp",
                callerArgs = callerArgs
            )
        )
    
      class SessionStorage(Storage):
  
        def get(self, key: str, callerArgs: Optional[dict]) -> str:
            return callerArgs["session"].get(key, None)
    
        def set(self, key: str, value: str, callerArgs: Optional[dict]) -> None:
            callerArgs["session"][key] = value
    
        def delete(self, key: str, callerArgs: Optional[dict]) -> None:
            callerArgs["session"].pop(key, None)
        
## References
  [SelfHosting OAuth Server](https://github.com/logto-io/logto/blob/master/docker-compose.yml)
  
  [Logto Python Client](https://github.com/logto-io/python/tree/master)

import os

from typing import Dict, Literal, Optional

import sys
libPath = f"./LIB/PyOAuthClient.pyz"
sys.path.insert(0,libPath )

from PyOAuthClient import OAuthClient, OAuthConfig, OAuthException, Storage

from fastapi import Request, Response
from starlette.responses import RedirectResponse
from mimetypes import guess_type
from fastapi import FastAPI

app = FastAPI()

from starlette_session import SessionMiddleware
app.add_middleware(SessionMiddleware, secret_key="secret", cookie_name="cookie22")

session = None

class SessionStorage(Storage):
    def get(self, key: str, callerArgs: Optional[dict]) -> str:
        return callerArgs["session"].get(key, None)

    def set(self, key: str, value: str, callerArgs: Optional[dict]) -> None:
        callerArgs["session"][key] = value

    def delete(self, key: str, callerArgs: Optional[dict]) -> None:
        callerArgs["session"].pop(key, None)


adminClient = OAuthClient(
    OAuthConfig(
        endpoint="<Your OAuth End Point>",
        appId="<Your OAuth ADMIN APP ID>",
        appSecret="<Your OAuth ADMIN APP Secret>",
        resources=[
            "https://default.logto.app/api or <Your Admin Appliction Resource Url>",
        ],  # Remove if you don't need to access the default Logto API
        scopes=["all"],
    ),
    SessionStorage(),
)

client = OAuthClient(
    OAuthConfig(
        endpoint="<Your OAuth End Point>",
        appId="<Your OAuth ADMIN APP ID>",
        appSecret="<Your OAuth ADMIN APP Secret>",
        resources=[
            "<Your Appliction Resource Url>",
        ],  # Remove if you don't need to access the default Logto API
        scopes=["email","custom_data", "chat:collection"],
    ),
    SessionStorage(),
)

from fastapi.responses import HTMLResponse

@app.get("/")
async def index(request: Request):
    try:
        global session
        callerArgs = { "session" : request.session }

        content = ""
        
        userList = await adminClient.fetchUserList("<Your Admin Appliction Resource Url>",callerArgs)

        if client.isAuthenticated(callerArgs = callerArgs) is False:
            content = "Not authenticated <a href='/signin'>Sign in</a>"
        else:
            callerArgs = { "session" : request.session }
            content = (
            (await client.fetchUserInfo(callerArgs = callerArgs)).model_dump_json(exclude_unset=True)
            + "<br>"
            + client.getIdTokenClaims(callerArgs = callerArgs).model_dump_json(exclude_unset=True)
            + "<br>"
            + str(userList)
            + "<br>"
            + (
                await client.getAccessTokenClaims("<Your Appliction Resource Url>",callerArgs)
            ).model_dump_json(exclude_unset=True)
            + "<br><a href='/sign-out'>Sign out</a>")
    except OAuthException as e:
        content = str(e) + "<br><a href='/sign-out'>Sign out</a>"

    return HTMLResponse(content="<html><body>" + content+ "</html></body>", status_code=200)

@app.get("/signin")
async def sign_in(request: Request):
    global session
    callerArgs = { "session" : request.session }
    return RedirectResponse(
        await client.signIn(
            redirectUri= request.base_url._url + "signin_callback",
            interactionMode="signUp",
            callerArgs = callerArgs
        )
    )

@app.get("/signout")
async def sign_out(request: Request):
    global session
    callerArgs = { "session" : request.session }
    return RedirectResponse(
        await client.signOut(postLogoutRedirectUri = request.base_url._url + "signin_callback", callerArgs = callerArgs)
    )


@app.get("/signin_callback")
async def callback(request: Request):
    try:
        global session
        callerArgs = { "session" : request.session }
        await client.handleSignInCallback(request.url._url, callerArgs = callerArgs)
        return RedirectResponse("/")
    except OAuthException as e:
        return str(e)
    
def Main():
    import uvicorn
    uvicorn.run("DemoWebServer:app",
                host="0.0.0.0",
                port=5000,
                ssl_keyfile="<SSL Key File Path>",
                ssl_certfile="<SSL Cert File Path>")

if __name__ == "__main__":
    Main()
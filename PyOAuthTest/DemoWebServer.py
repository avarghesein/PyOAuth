import os


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
    def get(self, key: str) -> str:
        return session.get(key, None)

    def set(self, key: str, value: str) -> None:
        session[key] = value

    def delete(self, key: str) -> None:
        session.pop(key, None)


adminClient = OAuthClient(
    OAuthConfig(
        endpoint="https://<Your OAuthServer IP or DNS>:3001",  # Replace with your Logto endpoint
        appId="Your admin app id",
        appSecret="Your admin app secret",
        resources=[
            "https://default.logto.app/api Or Your management application url",
        ],  # Remove if you don't need to access the default Logto API
        scopes=["all"],
    ),
    SessionStorage(),
)

client = OAuthClient(
    OAuthConfig(
        endpoint="https://<Your OAuthServer IP or DNS>:3001",  # Replace with your Logto endpoint
        appId="your app id",
        appSecret="your app secret",
        resources=[
            "https://<Your Protected API Resource>",
        ],  # Remove if you don't need to access the default Logto API
        scopes=["email","custom_data", "custom:permission"],
    ),
    SessionStorage(),
)

from fastapi.responses import HTMLResponse

@app.get("/")
async def index(request: Request):
    try:
        global session
        session = request.session

        content = ""
        
        userList = await adminClient.fetchUserList("https://default.logto.app/api")

        if client.isAuthenticated() is False:
            content = "Not authenticated <a href='/sign-in'>Sign in</a>"
        else:
            content = (
            (await client.fetchUserInfo()).model_dump_json(exclude_unset=True)
            + "<br>"
            + client.getIdTokenClaims().model_dump_json(exclude_unset=True)
            + "<br>"
            + str(userList)
            + "<br>"
            + (
                await client.getAccessTokenClaims("https://<Your Protected API Resource>")
            ).model_dump_json(exclude_unset=True)
            + "<br><a href='/sign-out'>Sign out</a>")
    except OAuthException as e:
        content = str(e) + "<br><a href='/sign-out'>Sign out</a>"

    return HTMLResponse(content="<html><body>" + content+ "</html></body>", status_code=200)

@app.get("/sign-in")
async def sign_in(request: Request):
    global session
    session = request.session
    return RedirectResponse(
        await client.signIn(
            redirectUri="http://<Your OAuthServer IP or DNS>:5000/callback", interactionMode="signUp"
        )
    )


@app.get("/sign-out")
async def sign_out(request: Request):
    global session
    session = request.session
    return RedirectResponse(
        await client.signOut(postLogoutRedirectUri="http://<Your OAuthServer IP or DNS>:5000/")
    )


@app.get("/callback")
async def callback(request: Request):
    try:
        global session
        session = request.session
        await client.handleSignInCallback(request.url._url)
        return RedirectResponse("/")
    except OAuthException as e:
        return str(e)
    
def Main():
    import uvicorn
    uvicorn.run("DemoWebServer:app",
                host="0.0.0.0",
                port=5000)

if __name__ == "__main__":
    Main()

import httpx

tokenUrl = "https://<host>:3001/oidc/token"
userUrl = "https://<host>:3001/api/users"

import base64
token = base64.b64encode(b'<admin token>')

with httpx.Client(http2=True, verify=False) as client:
    response = client.post(tokenUrl, data={
                "grant_type": "client_credentials",
                "resource": "https://default.logto.app/api",
                'client_id': '<clientid>',
                'client_secret': '<client secret>',
                'scope': 'all'})
    
    response_data = response.json()
    actoken= response_data["access_token"]

    users = client.get(userUrl,headers={"Authorization": f"Bearer {actoken}"})

print(users)
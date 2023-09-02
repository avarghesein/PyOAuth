## Have your SSL Certificates

### Create a Self Signed Certificate in Home Directory

    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./self.key -out ./self.crt
    sudo openssl x509 -req -days 365 -in csr.pem -signkey self.key -out self.crt

### Build and Run Your container with Mounting the Certificate Directory [SelfHostOAuthServer.yml]

    docker compose -p oauthserver up


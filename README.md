# reg-pilot-api
A service to manage regulator portal requests/responses that require authentication, document submission and validation. 

## Architecture

### Server (this service)
Provides the ability to:
* Log in using a vLEI ECR
* Upload signed files
* Check the status of an upload

#### Running locally:
After you have built the project locally (ex python -m pip install -e .)
In your terminal from the root project dir:

``` 
python src/regps/app/fastapi_app.py 
```

#### Running in Docker:
```
docker-compose build --no-cache
docker-compose down
docker-compose up
```

### Webapp
The web app (UI front-end) uses Signify/KERIA for selecting identifiers and credentials:
See: [reg-pilot-webapp](https://github.com/GLEIF-IT/reg-pilot-webapp)

### Verifier
The verifier uses [keripy](https://github.com/WebOfTRust/keripy) for verifying the requets:
See: [vlei-verifier](https://github.com/GLEIF-IT/vlei-verifier)

### Additional service
* KERI Witness Network
* vLEI Verifier
* KERI Agent

#### REST API
 You can run a test query using Swagger by going to:
 ```
 http://127.0.0.1:8000/docs
 ```


FROM weboftrust/keri:1.2.0-dev13

WORKDIR /usr/local/var

RUN mkdir server
COPY . /usr/local/var/server
RUN ls -la /usr/local/var/server
WORKDIR /usr/local/var/server/

RUN pip install -r requirements.txt

ENTRYPOINT [ "python","/usr/local/var/server/src/regps/app/fastapi_app.py" ]

FROM 2byrds/keri:1.1.7

WORKDIR /usr/local/var

RUN mkdir server
COPY . /usr/local/var/server
RUN ls -la /usr/local/var/server
WORKDIR /usr/local/var/server/

RUN pip install -r requirements.txt

ENTRYPOINT [ "gunicorn", "regps.app.service:app", "-b", "0.0.0.0:8000"]

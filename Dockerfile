FROM python:3.12-alpine
RUN adduser -u 1000 -D shadycompass
RUN apk add gcc git musl-dev
COPY . /opt/shadycompass
WORKDIR /opt/shadycompass
RUN python3 -m pip install -r requirements.txt
VOLUME /data
WORKDIR /data
USER 1000
ENTRYPOINT ["python3","/opt/shadycompass/shadycompass.py"]

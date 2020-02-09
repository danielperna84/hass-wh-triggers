FROM python:3-alpine
LABEL maintainer="Daniel Perna <danielperna84@gmail.com>"
RUN apk update && \
    apk upgrade && \
    apk add --no-cache python3-dev openssl-dev libffi-dev gcc musl-dev && \
    pip install --no-cache-dir hass-wh-triggers gunicorn
EXPOSE 8443
VOLUME /config
ENV APP_CONFIG_FILE=/config/config.cfg
CMD [ "gunicorn", "-w", "4", "--bind", "0.0.0.0:8443", "hass_wh_triggers.app:app", "--certfile=/config/server.crt", "--keyfile=/config/server.key" ]

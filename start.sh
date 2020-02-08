#!/bin/bash
export FLASK_APP=wsgi.py
export FLASK_DEBUG=0
export APP_CONFIG_FILE=/tmp/config.cfg
flask run --cert=adhoc --host=0.0.0.0 --port=8443
# flask run --cert=/etc/ssl/certs/yourcert.pem --key=/etc/ssl/private/yourkey.pem --host=0.0.0.0 --port=8443
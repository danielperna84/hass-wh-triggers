#!/usr/bin/env python

from app import app
from db import db
from models import Setting


def main():
    with app.app_context():
        db.create_all()
        title = Setting(parameter="title", value="HASS-WH-Triggers")
        db.session.add(title)
        session_timeout = Setting(parameter="session_timeout", value="15")
        db.session.add(session_timeout)
        ban_limit = Setting(parameter="ban_limit", value="3")
        db.session.add(ban_limit)
        ban_time = Setting(parameter="ban_time", value="300")
        db.session.add(ban_time)
        ignore_ssl = Setting(parameter="ignore_ssl", value="0")
        db.session.add(ignore_ssl)
        totp = Setting(parameter="totp", value="1")
        db.session.add(totp)
        db.session.commit()


if __name__ == '__main__':
    main()

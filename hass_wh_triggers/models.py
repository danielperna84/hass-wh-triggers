import time

from db import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    ukey = db.Column(db.String(20), unique=True, nullable=False)
    created = db.Column(db.Integer, default=0)
    credential_id = db.Column(db.String(250), unique=True, nullable=False)
    display_name = db.Column(db.String(160), unique=False, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    failed_logins = db.Column(db.Integer, default=0)
    last_login = db.Column(db.Integer, default=0)
    last_failed = db.Column(db.Integer, default=0)
    pub_key = db.Column(db.String(65), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    rp_id = db.Column(db.String(253), nullable=False)
    icon_url = db.Column(db.String(2083), nullable=False)

    def __init__(self, *args, **kwargs):
        self.created = int(time.time())
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return '<User %r %r>' % (self.display_name, self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def failed(self):
        self.failed_logins += 1
        self.last_failed = int(time.time())
        db.session.commit()

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    parameter = db.Column(db.String(32), unique=True, nullable=False)
    value = db.Column(db.String(128), unique=True, nullable=False)

    def __repr__(self):
        return '<Setting %r %r>' % (self.parameter, self.value)

class Trigger(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    caption = db.Column(db.String(64), unique=False, nullable=False)
    order = db.Column(db.Integer, unique=False, default=1)
    trigger_json = db.Column(db.String(512), unique=False, nullable=False)
    include_user = db.Column(db.Boolean, default=True, nullable=False)
    webhook_uri = db.Column(db.String(512), unique=False, nullable=False)
    password = db.Column(db.String(128), unique=False, nullable=False)

    def __repr__(self):
        return '<Trigger %r %r %r>' % (self.caption, self.order, self.include_user)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    token = db.Column(db.String(64), nullable=False)
    created = db.Column(db.Integer, default=0)

    def __init__(self, *args, **kwargs):
        self.created = int(time.time())
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return '<Token %r>' % (self.token)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

class Banlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    ip = db.Column(db.String(36), unique=False, nullable=False)
    last_attempt = db.Column(db.Integer, default=0)
    failed_attempts = db.Column(db.Integer, default=0)

    def __repr__(self):
        return '<Banlist %r %r %r>' % (self.ip, self.last_attempt, self.failed_attempts)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def increment(self):
        self.failed_attempts += 1
        self.last_attempt = int(time.time())
        db.session.commit()
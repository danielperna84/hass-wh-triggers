# pylint: disable=no-member

import os
import sys
import ssl
import time
import json
import random
import base64
import signal
import datetime
import urllib.request

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from flask import Flask
from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import abort
from flask_login import LoginManager
from flask_login import login_required
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.security import generate_password_hash

from . import util

from .db import db
from .models import User, Trigger, RegToken, Banlist, Setting, Authenticator, OTPToken, TriggerUserMap

from .fido2.webauthn import PublicKeyCredentialRpEntity
from .fido2.client import ClientData
from .fido2.server import Fido2Server
from .fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
from .fido2 import cbor

import pyotp

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('hass_wh_triggers.config.Config')
try:
    app.config.from_envvar('APP_CONFIG_FILE')
except:
    app.logger.info("Using default configuration")
if app.config.get('PREFIX'):
    app.wsgi_app = util.ReverseProxied(app.wsgi_app, script_name=app.config['PREFIX'])
db.init_app(app)
with app.app_context():
    db.create_all()
    if not Setting.query.all():
        title = Setting(parameter="title", value="HASS-WH-Triggers")
        db.session.add(title)
        session_timeout = Setting(parameter="session_timeout", value="15")
        db.session.add(session_timeout)
        ban_limit = Setting(parameter="ban_limit", value="3")
        db.session.add(ban_limit)
        ban_time = Setting(parameter="ban_time", value="300")
        db.session.add(ban_time)
        maxfido = Setting(parameter="maxfido", value="1")
        db.session.add(maxfido)
        ignore_ssl = Setting(parameter="ignore_ssl", value="0")
        db.session.add(ignore_ssl)
        totp = Setting(parameter="totp", value="1")
        db.session.add(totp)
        db.session.commit()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

RP_ID = app.config['RP_ID']
ORIGIN = app.config['ORIGIN']

RP = PublicKeyCredentialRpEntity(RP_ID, "HASS-WH-Triggers")
server = Fido2Server(RP)

VERSION = "0.0.7"
if isinstance(app.secret_key, bytes):
    ENCRYPTION_KEY = app.secret_key
else:
    ENCRYPTION_KEY = app.secret_key.encode("utf-8")
SITE_URL = 'https://example.com'
TITLE = 'HASS-WH-Triggers'
SESSION_TIMEOUT = 15
BANLIMIT = 3
BANTIME = 60
MAXFIDO = 1
TOTP = True
IGNORE_SSL = False
SSL_DEFAULT = ssl._create_default_https_context
SSL_UNVERIFIED = ssl._create_unverified_context
IS_GUNICORN = "gunicorn" in os.environ.get("SERVER_SOFTWARE", "")

def load_settings():
    global TITLE, SESSION_TIMEOUT, BANLIMIT, BANTIME, MAXFIDO, TOTP, IGNORE_SSL, ssl
    TITLE = Setting.query.filter_by(parameter='title').first().value
    SESSION_TIMEOUT = int(Setting.query.filter_by(parameter='session_timeout').first().value)
    BANLIMIT = int(Setting.query.filter_by(parameter='ban_limit').first().value)
    BANTIME = int(Setting.query.filter_by(parameter='ban_time').first().value)
    MAXFIDO = int(Setting.query.filter_by(parameter='maxfido').first().value)
    TOTP = bool(int(Setting.query.filter_by(parameter='totp').first().value))
    IGNORE_SSL = bool(int(Setting.query.filter_by(parameter='ignore_ssl').first().value))
    if IGNORE_SSL:
        ssl._create_default_https_context = SSL_UNVERIFIED
    else:
        ssl._create_default_https_context = SSL_DEFAULT

with app.app_context():
    try:
        load_settings()
    except:
        pass


def checkban(addr):
    banned = Banlist.query.filter_by(ip=addr).first()
    if banned:
        if time.time() - banned.last_attempt > BANTIME:
            banned.delete()
        elif banned.failed_attempts > BANLIMIT and time.time() - banned.last_attempt < BANTIME:
            banned.increment()
            app.logger.warning("Denying access from: %s", addr)
            return False
    return True


def add_to_ban(addr):
    app.logger.warning("Adding to banlist: %s", addr)
    banned = Banlist.query.filter_by(ip=request.remote_addr).first()
    if not banned:
        banned = Banlist(
            ip=addr,
            failed_attempts=1,
            last_attempt=int(time.time())
        )
        db.session.add(banned)
        db.session.commit()
    else:
        banned.increment()


def unban(addr):
    banned = Banlist.query.filter_by(ip=request.remote_addr).first()
    if banned:
        app.logger.warning("Removing from banlist: %s", addr)
        banned.delete()

@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None
    return User.query.get(int(user_id))


@app.before_request
def before_request():
    if ORIGIN not in request.host_url:
        app.logger.warning('Incorrect hostname (%s), rejecting request', request.host_url)
        add_to_ban(request.remote_addr)
        abort(401)
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=SESSION_TIMEOUT)
    session.modified = True


@app.context_processor
def inject_dict_for_all_templates():
    return dict(app_title=TITLE, debug=app.debug, version=VERSION)


@app.template_filter('ctime')
def timectime(s):
    return time.ctime(s)


@app.route('/manifest.json')
def pwa_manifest():
    return render_template('pwa-manifest.json')


@app.route('/index')
@app.route('/')
def index():
    if not checkban(request.remote_addr):
        abort(401)
    if current_user.is_authenticated:
        return redirect(url_for('triggers'))
    users = User.query.all()
    if not users:
        return redirect(url_for('register_prompt', reg_token="none"))
    return render_template('index.html', totp=TOTP)


@app.route('/about')
def about():
    if not checkban(request.remote_addr):
        abort(401)
    return render_template('about.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    title = Setting.query.filter_by(parameter='title').first()
    session_timeout = Setting.query.filter_by(parameter='session_timeout').first()
    ban_limit = Setting.query.filter_by(parameter='ban_limit').first()
    ban_time = Setting.query.filter_by(parameter='ban_time').first()
    maxfido = Setting.query.filter_by(parameter='maxfido').first()
    totp = Setting.query.filter_by(parameter='totp').first()
    ignore_ssl = Setting.query.filter_by(parameter='ignore_ssl').first()
    if request.method == 'POST':
        title.value = request.values.get('title')
        db.session.add(title)
        session_timeout.value = request.values.get('session_timeout')
        db.session.add(session_timeout)
        ban_limit.value = request.values.get('ban_limit')
        db.session.add(ban_limit)
        ban_time.value = request.values.get('ban_time')
        db.session.add(ban_time)
        maxfido.value = request.values.get('maxfido')
        db.session.add(maxfido)
        totp.value = '1' if request.values.get('totp') else '0'
        db.session.add(totp)
        ignore_ssl.value = '1' if request.values.get('ignore_ssl') else '0'
        db.session.add(ignore_ssl)
        db.session.commit()
        if IS_GUNICORN:
            app.logger.warning("Sending HUP to %i", os.getppid())
            os.kill(os.getppid(), signal.SIGHUP)
        load_settings()
    return render_template('settings.html', title=TITLE,
                           session_timeout=SESSION_TIMEOUT,
                           ban_limit=BANLIMIT, ban_time=BANTIME, maxfido=MAXFIDO,
                           totp='checked' if TOTP else '',
                           ignore_ssl='checked' if IGNORE_SSL else '')


@app.route('/banlist', methods=['GET'])
@login_required
def banlist():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    del_banned = request.args.get('del_banned')
    if del_banned:
        banned = Banlist.query.filter_by(id=del_banned).first()
        if banned:
            banned.delete()
        return redirect(url_for('banlist'))
    purge = request.args.get('purge')
    if purge:
        for ip in Banlist.query.all():
            ip.delete()
        return redirect(url_for('banlist'))
    banlist = Banlist.query.all()
    return render_template('banlist.html', banlist=banlist)


@app.route('/register/<reg_token>')
def register_prompt(reg_token):
    if not checkban(request.remote_addr):
        abort(401)
    if User.query.all():
        token = RegToken.query.filter_by(token=reg_token).first()
        if not token:
            add_to_ban(request.remote_addr)
            abort(401)
    if current_user.is_authenticated:
        return redirect(url_for('triggers'))
    return render_template('register.html', reg_token=reg_token)


@app.route('/register', methods=['POST'])
def register():
    if not checkban(request.remote_addr):
        abort(401)
    token = None
    otp_only = False
    username = request.form.get('register_username')
    password_hash = generate_password_hash(request.form.get('register_password'))
    display_name = username
    reg_token = request.form.get('register_reg_token')

    if User.query.all():
        token = RegToken.query.filter_by(token=reg_token).first()
        if not token:
            app.logger.warning("Invalid token")
            add_to_ban(request.remote_addr)
            return make_response(jsonify({'status': 'error'}), 401)
        if token:
            now = int(time.time())
            if now - token.created > token.max_age:
                token.delete()
                flash("Registration token has expired. Please acquire a new one.")
                return redirect(url_for('register_prompt', reg_token=reg_token))
            otp_only = token.otp_only
    if not util.validate_username(username):
        flash("Invalid username")
        return redirect(url_for('register_prompt', reg_token=reg_token))

    if User.query.filter_by(username=username).first():
        flash("User already exists")
        return redirect(url_for('register_prompt', reg_token=reg_token))

    is_admin = not bool(User.query.all())

    user = User(
        username=username,
        display_name=display_name,
        is_admin=is_admin,
        otp_only=otp_only,
        password_hash=password_hash,
        sign_count=0,
        totp_enabled=TOTP,
        last_login=int(time.time()),
        icon_url=SITE_URL)
    db.session.add(user)
    db.session.commit()

    if token:
        token.delete()
    login_user(user)
    return redirect(url_for('security'))


@app.route('/users/import', methods=['POST'])
@login_required
def users_import():
    if not checkban(request.remote_addr):
        abort(401)
    if not current_user.is_admin:
        redirect(url_for('triggers'))
    data = request.get_json()
    user = User(
        created=data['created'],
        username=data['username'],
        display_name=data['display_name'],
        is_admin=data['is_admin'],
        otp_only=data['otp_only'],
        password_hash=data['password_hash'],
        sign_count=data['sign_count'],
        last_failed=data['last_failed'],
        last_login=data['last_login'],
        totp_enabled=data['totp_enabled'],
        totp_initialized=data['totp_initialized'],
        totp_secret=data['totp_secret'].encode('utf-8'),
        icon_url=data['icon_url'])
    db.session.add(user)
    db.session.commit()

    return make_response(jsonify({"status": "success"}), 200)


@app.route('/authenticators/import', methods=['POST'])
@login_required
def authenticators_import():
    if not checkban(request.remote_addr):
        abort(401)
    if not current_user.is_admin:
        redirect(url_for('triggers'))
    data = request.get_json()
    app.logger.debug(data)
    authenticator = Authenticator(
        credential=base64.b64decode(data['credential'].encode('utf-8')),
        user=int(data['user']),
        name=data['name'])
    db.session.add(authenticator)
    db.session.commit()

    return make_response(jsonify({"status": "success"}), 200)


### This is only accessible when Flasks Debug mode is turned on!
@app.route('/login/debug', methods=['POST'])
def login_debug():
    if not app.config['DEBUG']:
        abort(401)
    if not checkban(request.remote_addr):
        abort(401)
    username = request.form.get('login_username')
    password = request.form.get('login_password')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not user.check_password(password):
        return make_response(jsonify({'fail': 'Wrong password'}), 401)
    login_user(user)
    user.sign_count = user.sign_count + 1
    user.last_login = int(time.time())
    db.session.add(user)
    db.session.commit()
    unban(request.remote_addr)
    return redirect(url_for('security'))


@app.route("/login/otp", methods=["POST"])
def login_otp():
    if not checkban(request.remote_addr):
        abort(401)
    username = request.form.get('login_username')
    password = request.form.get('login_password')
    totp = request.form.get('login_totp')
    otp = request.form.get('login_otp')

    if not util.validate_username(username):
        add_to_ban(request.remote_addr)
        app.logger.warning("Invalid username")
        return make_response(jsonify({'status': 'error'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        add_to_ban(request.remote_addr)
        app.logger.warning("User does not exist")
        return make_response(jsonify({'status': 'error'}), 401)
    if not user.check_password(password):
        user.failed()
        add_to_ban(request.remote_addr)
        app.logger.warning("Wrong password")
        return make_response(jsonify({'status': 'error'}), 401)

    otps = []
    for otp in OTPToken.query.filter_by(user=user.id):
        otps.append(otp)

    if not user.totp_secret and not otps:
        user.failed()
        add_to_ban(request.remote_addr)
        app.logger.warning("No (T)OTP available")
        return make_response(jsonify({'status': 'error'}), 401)

    if TOTP and totp:
        if user.totp_enabled and user.totp_secret and not user.otp_only:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                            salt=username.encode("utf-8"),
                            iterations=100000, backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY))
            f = Fernet(key)
            try:
                if pyotp.totp.TOTP(f.decrypt(user.totp_secret)).verify(totp, valid_window=1):
                    login_user(user)
                    user.sign_count = user.sign_count + 1
                    user.last_login = int(time.time())
                    user.totp_initialized = True
                    db.session.add(user)
                    db.session.commit()
                    unban(request.remote_addr)
                    return make_response(jsonify({'status': 'success'}), 200)
            except InvalidToken:
                app.logger.warning("Invalid TOTP. Server secret key may has changed")
            app.logger.warning("Incorrect TOTP")

    if otp and otps:
        now = int(time.time())
        for otp_token in otps:
            if now - otp_token.created < otp_token.max_age:
                otp_token.delete()
                login_user(user)
                user.sign_count = user.sign_count + 1
                user.last_login = int(time.time())
                db.session.add(user)
                db.session.commit()
                unban(request.remote_addr)
                return make_response(jsonify({'status': 'success'}), 200)
        app.logger.warning("Invalid OTP")

    user.failed()
    add_to_ban(request.remote_addr)
    return make_response(jsonify({'status': 'error'}), 401)


@app.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    user = User.query.filter_by(username=current_user.username).first()
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        if not user.check_password(current_password):
            flash("Incorrect password.")
            return redirect(url_for('security'))
        user.password_hash = generate_password_hash(request.form.get('password'))
        db.session.add(user)
        db.session.commit()
        flash("Password saved.")
        return redirect(url_for('security'))
    totp_enabled = bool(int(Setting.query.filter_by(parameter='totp').first().value))
    del_authenticator = request.args.get('del_authenticator')
    if del_authenticator:
        if current_user.is_admin:
            authenticator = Authenticator.query.filter_by(id=del_authenticator).first()
        else:
            authenticator = Authenticator.query.filter_by(id=del_authenticator).filter_by(user=current_user.id).first()
        if authenticator:
            authenticator.delete()
        return redirect(url_for('security'))
    authenticators = []
    for authenticator in Authenticator.query.filter_by(user=current_user.id):
        authenticators.append({'id': authenticator.id, 'name': authenticator.name, 'user': authenticator.user})
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=user.username.encode("utf-8"),
                     iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY))
    f = Fernet(key)
    totp_secret = None
    totp_uri = ""
    if user.totp_secret:
        try:
            totp_secret = f.decrypt(bytes(user.totp_secret)).decode("utf-8")
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=current_user.username, issuer_name=TITLE)
        except InvalidToken:
            app.logger.warning("Invalid token. Server secret key may has changed.")
            totp_secret = "Invalid"
    if not totp_secret == "Invalid":
        if totp_secret is not None and user.totp_initialized:
            totp_secret = "Initialized"
            totp_uri = ""

    return render_template('security.html', authenticators=authenticators,
                           totp_secret=totp_secret, totp_uri=totp_uri,
                           totp_enabled=totp_enabled, user=user, maxfido=MAXFIDO)

@app.route('/tokens', methods=['GET'])
@login_required
def tokens():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    del_token = request.args.get('del_token')
    if del_token:
        token = RegToken.query.filter_by(id=del_token).first()
        if token:
            token.delete()
        return redirect(url_for('tokens'))
    now = time.time()
    for token in RegToken.query.all():
        if now - token.created > token.max_age:
            token.delete()
    tokens = RegToken.query.all()
    return render_template('tokens.html', tokens=tokens, baseurl=request.url_root + 'register/')


@app.route('/tokens/add', methods=['POST'])
@login_required
def tokens_add():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    max_age = request.values.get('max_age')
    otp_only = True if request.values.get('otp_only') == '1' else False
    token = RegToken(
        token="%064x" % random.getrandbits(256),
        max_age=int(max_age) * 60,
        otp_only=otp_only)
    db.session.add(token)
    db.session.commit()
    return make_response(jsonify({'success': token.id}), 200)


@app.route('/otp', methods=['GET'])
@login_required
def otp():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    del_token = request.args.get('del_token')
    if del_token:
        token = OTPToken.query.filter_by(id=del_token).first()
        if token:
            token.delete()
        return redirect(url_for('otp'))
    now = time.time()
    for token in OTPToken.query.all():
        if now - token.created > token.max_age:
            token.delete()
    tokens = OTPToken.query.all()
    users = User.query.all()
    usermap = {}
    for user in users:
        usermap[user.id] = user.username
    return render_template('otp.html', tokens=tokens, users=users, usermap=usermap, baseurl=request.url_root + 'index?otp=')


@app.route('/otp/add', methods=['POST'])
@login_required
def otp_add():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    user = request.values.get('user')
    max_age = request.values.get('max_age')
    token = OTPToken(
        token="%064x" % random.getrandbits(256),
        max_age=int(max_age) * 60,
        user=int(user)
        )
    db.session.add(token)
    db.session.commit()
    return make_response(jsonify({'success': token.id}), 200)


@app.route('/totp/generate')
@login_required
def totp_generate():
    user = User.query.filter_by(username=current_user.username).first()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=user.username.encode("utf-8"),
                     iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY))
    f = Fernet(key)
    user.totp_secret = f.encrypt(pyotp.random_base32().encode("utf-8"))
    user.totp_initialized = False
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({"status": "success"}), 200)


@app.route('/totp/delete')
@login_required
def totp_delete():
    user = User.query.filter_by(username=current_user.username).first()
    user.totp_secret = b""
    user.totp_initialized = False
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({"status": "success"}), 200)


@app.route('/totp/delete/<username>')
@login_required
def totp_delete_username(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return make_response(jsonify({"status": "error"}), 200)
    user.totp_secret = b""
    user.totp_initialized = False
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({"status": "success"}), 200)


@app.route('/authenticators/<int:authenticatorid>')
@login_required
def authenticators_json(authenticatorid):
    authenticator = Authenticator.query.filter_by(id=authenticatorid).first()
    authenticator = {
        "name": authenticator.name,
        "credential": base64.b64encode(authenticator.credential).decode('utf-8')
    }
    return make_response(jsonify(authenticator), 200)


@app.route('/users', methods=['GET'])
@login_required
def users():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    del_user = request.args.get('del_user')
    if del_user:
        user = User.query.filter_by(id=del_user).first()
        if user:
            for authenticator in Authenticator.query.filter_by(user=user.id):
                authenticator.delete()
            user.delete()
            TriggerUserMap.query.filter_by(user=user.id).delete()
            db.session.commit()
        return redirect(url_for('users'))
    users = User.query.all()
    usermap = {}
    for user in users:
        usermap[user.id] = user.username
    authenticators = []
    for authenticator in Authenticator.query.all():
        authenticators.append({'id': authenticator.id, 'name': authenticator.name, 'user': authenticator.user})
    return render_template('users.html', users=users, usermap=usermap, authenticators=authenticators)


@app.route('/users/<int:userid>')
@login_required
def users_json(userid):
    user = User.query.filter_by(id=userid).first()
    userdata = {
        "username": user.username,
        "display_name": user.display_name,
        "created": user.created,
        "password_hash": user.password_hash,
        "is_admin": user.is_admin,
        "sign_count": user.sign_count,
        "failed_logins": user.failed_logins,
        "last_login": user.last_login,
        "last_failed": user.last_failed,
        "icon_url": user.icon_url,
        "totp_enabled": user.totp_enabled,
        "totp_initialized": user.totp_initialized,
        "otp_only": user.otp_only
    }
    if user.totp_secret is not None:
        userdata["totp_secret"] = user.totp_secret.decode('utf-8')
    return make_response(jsonify(userdata), 200)


@app.route('/users/toggle_admin/<int:userid>')
@login_required
def users_toggle_admin(userid):
    if not current_user.is_admin:
        return make_response(jsonify({'fail': 'unauthorized'}), 401)
    user = load_user(userid)
    user.is_admin = not user.is_admin
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({'success': user.is_admin}), 200)


@app.route('/users/toggle_otp/<int:userid>')
@login_required
def users_toggle_otp(userid):
    if not current_user.is_admin:
        return make_response(jsonify({'fail': 'unauthorized'}), 401)
    user = load_user(userid)
    user.otp_only = not user.otp_only
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({'success': user.otp_only}), 200)


@app.route('/users/toggle_totp/<int:userid>')
@login_required
def users_toggle_totp(userid):
    if not current_user.is_admin:
        return make_response(jsonify({'fail': 'unauthorized'}), 401)
    user = load_user(userid)
    user.totp_enabled = not user.totp_enabled
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({'success': user.totp_enabled}), 200)


@app.route('/triggers')
@login_required
def triggers():
    available_triggers = [ x.trigger for x in TriggerUserMap.query.filter_by(user=current_user.id).all() ]
    triggers = Trigger.query.filter_by(disabled=False).order_by(Trigger.order.asc()).all()
    triggers = [ t for t in triggers if t.id in available_triggers ]
    return render_template('triggers.html', triggers=triggers)


@app.route('/triggers/<int:triggerid>')
@login_required
def triggers_json(triggerid):
    trigger = Trigger.query.filter_by(id=triggerid).first()
    trigger = {
        "id": trigger.id,
        "caption": trigger.caption,
        "order": trigger.order,
        "trigger_json": trigger.trigger_json,
        "include_user": trigger.include_user,
        "require_geo": trigger.require_geo,
        "disabled": trigger.disabled,
        "webhook_uri": trigger.webhook_uri,
        "password": trigger.password,
        "users": []
    }
    usermap = TriggerUserMap.query.filter_by(trigger=triggerid).all()
    for user in usermap:
        trigger["users"].append(user.user)
    return make_response(jsonify(trigger), 200)


@app.route('/triggers/fire/<int:triggerid>', methods=['POST'])
@login_required
def triggers_fire(triggerid):
    trigger = Trigger.query.filter_by(id=triggerid).first()
    if trigger.disabled:
        return make_response(jsonify({"status": "error", "error": "trigger disabled"}), 401)
    available_triggers = [ x.trigger for x in TriggerUserMap.query.filter_by(user=current_user.id).all() ]
    if trigger.id not in available_triggers:
        return make_response(jsonify({"status": "error", "error": "trigger not available to user"}), 401)
    postdata = request.get_json()
    password = postdata.get('password')
    if trigger.password and not password:
        return make_response(jsonify({"status": "error", "error": "missing password"}), 401)
    if password and trigger.password:
        if password != trigger.password:
            return make_response(jsonify({"status": "error", "error": "invalid password"}), 401)
    headers = {
        "Content-Type": "application/json"
    }
    data = json.loads(trigger.trigger_json)
    if trigger.include_user:
        data['user'] = current_user.username
    if trigger.require_geo:
        data['latitude'] = postdata.get('latitude')
        data['longitude'] = postdata.get('longitude')
        data['accuracy'] = postdata.get('accuracy')
    app.logger.warning("Trigger fired by %s: %s", current_user.username, trigger.caption)
    req = urllib.request.Request(trigger.webhook_uri,
                                 headers=headers, method='POST',
                                 data=bytes(json.dumps(data).encode('utf-8')))
    try:
        with urllib.request.urlopen(req) as response:
            if response.code != 200:
                app.logger.warning("Trigger failed: %s", trigger.caption)
                return make_response(jsonify({"status": "failed", "trigger": trigger.id}), 200)
    except Exception as err:
        app.logger.warning(err)
        return make_response(jsonify({"status": "failed", "trigger": trigger.id}), 200)
    return make_response(jsonify({"status": "success", "trigger": trigger.id}), 200)


@app.route('/admin_triggers', methods=['GET', 'POST'])
@login_required
def admin_triggers():
    if request.method == 'GET':
        del_trigger = request.args.get('del_trigger')
        if del_trigger:
            trigger = Trigger.query.filter_by(id=del_trigger).first()
            if trigger:
                trigger.delete()
                TriggerUserMap.query.filter_by(trigger=del_trigger).delete()
                db.session.commit()
            return redirect(url_for('admin_triggers'))
    elif request.method == 'POST':
        trigger_id = request.values.get('id')
        caption = request.values.get('caption')
        order = int(request.values.get('order'))
        trigger_json = json.loads(request.values.get('trigger_json'))
        include_user = True if request.values.get('include_user') else False
        require_geo = True if request.values.get('require_geo') else False
        disabled = True if request.values.get('disabled') else False
        webhook_uri = request.values.get('webhook_uri')
        password = request.values.get('password')
        users = request.form.getlist('users')
        trigger_json = json.dumps(trigger_json)
        if not trigger_id:
            trigger = Trigger(
                caption=caption,
                order=order,
                trigger_json=trigger_json,
                include_user=include_user,
                require_geo=require_geo,
                disabled=disabled,
                webhook_uri=webhook_uri,
                password=password
            )
            db.session.add(trigger)
            db.session.commit()
            for user in users:
                trigger_user = TriggerUserMap(
                    trigger=int(trigger.id),
                    user=int(user)
                )
                db.session.add(trigger_user)
        else:
            trigger = Trigger.query.get(int(trigger_id))
            trigger.caption = caption
            trigger.order = order
            trigger.trigger_json = trigger_json
            trigger.include_user = include_user
            trigger.require_geo = require_geo
            trigger.disabled = disabled
            trigger.webhook_uri = webhook_uri
            trigger.password = password
            db.session.add(trigger)
            TriggerUserMap.query.filter_by(trigger=trigger.id).delete()
            for user in users:
                trigger_user = TriggerUserMap(
                    trigger=int(trigger.id),
                    user=int(user)
                )
                db.session.add(trigger_user)
        db.session.commit()
    triggers = Trigger.query.all()
    users = User.query.all()
    return render_template('admin_triggers.html', triggers=triggers, users=users)


@app.route("/api/register/begin", methods=["POST"])
@login_required
def register_begin():
    user = load_user(current_user.id)
    authenticators = Authenticator.query.filter_by(user=user.id).all()
    if len(authenticators) >= MAXFIDO:
        app.logger.warning("No additional tokens allowed")
        return make_response(jsonify({'fail': 'error'}), 401)
    authenticators = []
    registration_data, state = server.register_begin(
        {
            "id": b"%i" % current_user.id,
            "name": current_user.username,
            "displayName": current_user.display_name,
            "icon": "https://example.com/image.png",
        },
        authenticators,
        user_verification="discouraged", # "required", "preferred", "discouraged"
        # https://w3c.github.io/webauthn/#enum-userVerificationRequirement
        # https://w3c.github.io/webauthn/#user-verification
        authenticator_attachment=None, # "platform", "cross-platform", None for both
        # https://w3c.github.io/webauthn/#enum-attachment
        # https://w3c.github.io/webauthn/#platform-attachment
    )

    session['token_name'] = request.form.get('token_name')
    session['user_id'] = current_user.id
    session["state"] = state
    return cbor.encode(registration_data)


@app.route("/api/register/complete", methods=["POST"])
@login_required
def register_complete():
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    auth_data = server.register_complete(session["state"], client_data, att_obj)
    authenticator = Authenticator(
        credential=auth_data.credential_data,
        user=int(session['user_id']),
        name=session['token_name'])
    db.session.add(authenticator)
    db.session.commit()
    return cbor.encode({"status": "OK"})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    if not checkban(request.remote_addr):
        abort(401)
    if not Authenticator.query.all():
        abort(401)

    username = request.form.get('login_username')
    password = request.form.get('login_password')

    if not util.validate_username(username):
        app.logger.warning("Invalid username")
        add_to_ban(request.remote_addr)
        return make_response(jsonify({'fail': 'error'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        app.logger.warning("User does not exist")
        add_to_ban(request.remote_addr)
        return make_response(jsonify({'fail': 'error'}), 401)
    if not user.check_password(password):
        app.logger.warning("Incorrect password")
        user.failed()
        add_to_ban(request.remote_addr)
        return make_response(jsonify({'fail': 'error'}), 401)

    authenticators = []
    for authenticator in Authenticator.query.filter_by(user=user.id):
        authenticators.append(AttestedCredentialData(authenticator.credential))
    if not authenticators:
        app.logger.warning("No authenticator enrolled")
        return make_response(jsonify({'fail': 'error'}), 401)
    auth_data, state = server.authenticate_begin(authenticators)
    session["state"] = state
    session["lid"] = user.id

    return cbor.encode(auth_data)


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    if not checkban(request.remote_addr):
        abort(401)
    if not Authenticator.query.all():
        abort(401)

    authenticators = []
    user = User.query.filter_by(id=int(session.pop("lid"))).first()
    for authenticator in Authenticator.query.filter_by(user=user.id):
        authenticators.append(AttestedCredentialData(authenticator.credential))
    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]

    server.authenticate_complete(
        session.pop("state"),
        authenticators,
        credential_id,
        client_data,
        auth_data,
        signature,
    )

    login_user(user)

    user.sign_count = user.sign_count + 1
    user.failed_logins = 0
    user.last_failed = 0
    user.last_login = int(time.time())
    db.session.add(user)
    db.session.commit()
    unban(request.remote_addr)
    return cbor.encode({"status": "OK"})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    #with app.app_context():
    #    db.create_all()
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)

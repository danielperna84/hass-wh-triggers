# pylint: disable=no-member

import os
import sys
import ssl
import time
import json
import random
import datetime
import urllib.request

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

import util

from db import db
from models import User, Trigger, RegToken, Banlist, Setting, Authenticator

from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
from fido2 import cbor

RP_ID = os.environ.get('RPID') if os.environ.get('RPID') else 'localhost'
ORIGIN = os.environ.get('ORIGIN') if os.environ.get('ORIGIN') else 'https://localhost:5000'

RP = PublicKeyCredentialRpEntity(RP_ID, "HASS-WH-Triggers")
server = Fido2Server(RP)

app = Flask(__name__, static_url_path="")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(
    os.path.join(os.path.dirname(os.path.abspath(__name__)), 'webauthn.db'))
app.config.update(
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    #SERVER_NAME=ORIGIN.split('/')[-1],
    #SESSION_COOKIE_SECURE=True
)
sk = os.environ.get('FLASK_SECRET_KEY')
app.secret_key = sk if sk else os.urandom(40)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

SITE_URL = 'https://example.com'

TITLE = 'HASS-WH-Triggers'
SESSION_TIMEOUT = 15
BANLIMIT = 3
BANTIME = 60
IGNORE_SSL = False
SSL_DEFAULT = ssl._create_default_https_context
SSL_UNVERIFIED = ssl._create_unverified_context

def load_settings():
    global TITLE, SESSION_TIMEOUT, BANLIMIT, BANTIME, IGNORE_SSL, ssl
    TITLE = Setting.query.filter_by(parameter='title').first().value
    SESSION_TIMEOUT = int(Setting.query.filter_by(parameter='session_timeout').first().value)
    BANLIMIT = int(Setting.query.filter_by(parameter='ban_limit').first().value)
    BANTIME = int(Setting.query.filter_by(parameter='ban_time').first().value)
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

def checkban(addr, increment=True):
    banned = Banlist.query.filter_by(ip=addr).first()
    if banned:
        if time.time() - banned.last_attempt > BANTIME:
            banned.delete()
        elif time.time() - banned.last_attempt < BANTIME and banned.failed_attempts > BANLIMIT:
            if increment:
                banned.increment()
            return False
    return True


def add_to_ban(addr):
    print("Adding to banlist: %s" % addr)
    banned = Banlist.query.filter_by(ip=request.remote_addr).first()
    if banned:
        banned.increment()
    else:
        banned = Banlist(
            ip=addr,
            failed_attempts=1,
            last_attempt=int(time.time())
        )
        db.session.add(banned)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None
    return User.query.get(int(user_id))


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=SESSION_TIMEOUT)
    session.modified = True


@app.context_processor
def inject_dict_for_all_templates():
    return dict(app_title=TITLE, debug=app.debug)


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
    return render_template('index.html')


@app.route('/about')
def about():
    if not checkban(request.remote_addr):
        abort(401)
    return render_template('about.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not checkban(request.remote_addr):
        abort(401)
    title = Setting.query.filter_by(parameter='title').first()
    session_timeout = Setting.query.filter_by(parameter='session_timeout').first()
    ban_limit = Setting.query.filter_by(parameter='ban_limit').first()
    ban_time = Setting.query.filter_by(parameter='ban_time').first()
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
        ignore_ssl.value = '1' if request.values.get('ignore_ssl') else '0'
        db.session.add(ignore_ssl)
        db.session.commit()
        load_settings()
    return render_template('settings.html', title=TITLE,
                           session_timeout=SESSION_TIMEOUT,
                           ban_limit=BANLIMIT, ban_time=BANTIME,
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
    banlist = Banlist.query.all()
    return render_template('banlist.html', banlist=banlist)


@app.route('/register/<reg_token>')
def register_prompt(reg_token):
    if User.query.all():
        token = RegToken.query.filter_by(token=reg_token).first()
        if not token:
            add_to_ban(request.remote_addr)
    if not checkban(request.remote_addr, increment=False):
        abort(401)
    if current_user.is_authenticated:
        return redirect(url_for('triggers'))
    return render_template('register.html', reg_token=reg_token)


@app.route('/register', methods=['POST'])
def register():
    if not checkban(request.remote_addr):
        abort(401)
    token = None
    username = request.form.get('register_username')
    password_hash = generate_password_hash(request.form.get('register_password'))
    display_name = username
    reg_token = request.form.get('register_reg_token')

    if User.query.all():
        token = RegToken.query.filter_by(token=reg_token).first()
        if not token:
            return make_response(jsonify({'fail': 'Invalid token.'}), 401)
    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    if not util.validate_display_name(display_name):
        return make_response(jsonify({'fail': 'Invalid display name.'}), 401)

    if User.query.filter_by(username=username).first():
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    is_admin = not bool(User.query.all())

    user = User(
        username=username,
        display_name=display_name,
        is_admin=is_admin,
        password_hash=password_hash,
        sign_count=0,
        icon_url=SITE_URL)
    db.session.add(user)
    db.session.commit()
    if token:
        token.delete()
    login_user(user)
    return redirect(url_for('zfa'))


### This is only accessible when Flasks Debug mode is turned on!
@app.route('/login', methods=['POST'])
def login():
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
        user.failed()
        add_to_ban(request.remote_addr)
        return make_response(jsonify({'fail': 'Wrong password'}), 401)
    login_user(user)
    return redirect(url_for('zfa'))


@app.route('/zfa', methods=['GET'])
@login_required
def zfa():
    del_authenticator = request.args.get('del_authenticator')
    if del_authenticator:
        if current_user.is_admin:
            authenticator = Authenticator.query.filter_by(id=del_authenticator).first()
        else:
            authenticator = Authenticator.query.filter_by(id=del_authenticator).filter_by(user=current_user.id).first()
        if authenticator:
            authenticator.delete()
        return redirect(url_for('zfa'))
    authenticators = []
    for authenticator in Authenticator.query.filter_by(user=current_user.id):
        authenticators.append({'id': authenticator.id, 'name': authenticator.name, 'user': authenticator.user})
    return render_template('2fa.html', authenticators=authenticators)

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
    tokens = RegToken.query.all()
    return render_template('tokens.html', tokens=tokens, baseurl=request.url_root + 'register/')


@app.route('/tokens/add')
@login_required
def tokens_add():
    if not current_user.is_admin:
        return redirect(url_for('triggers'))
    token = RegToken(token="%064x" % random.getrandbits(256))
    db.session.add(token)
    db.session.commit()
    return make_response(jsonify({'success': token.id}), 200)


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
        return redirect(url_for('users'))
    users = User.query.all()
    authenticators = []
    for authenticator in Authenticator.query.all():
        authenticators.append({'id': authenticator.id, 'name': authenticator.name, 'user': authenticator.user})
    return render_template('users.html', users=users, authenticators=authenticators)


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

@app.route('/triggers')
@login_required
def triggers():
    triggers = Trigger.query.order_by(Trigger.order.asc()).all()
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
        "webhook_uri": trigger.webhook_uri,
        "password": trigger.password,
    }
    return make_response(jsonify(trigger), 200)


@app.route('/triggers/fire/<int:triggerid>', methods=['POST'])
@login_required
def triggers_fire(triggerid):
    trigger = Trigger.query.filter_by(id=triggerid).first()
    password = request.values.get('password')
    if password:
        if password != trigger.password:
            return make_response(jsonify({"status": "error", "error": "invalid password"}), 401)
    headers = {
        "Content-Type": "application/json"
    }
    data = json.loads(trigger.trigger_json)
    if trigger.include_user:
        data['user'] = current_user.username
    req = urllib.request.Request(trigger.webhook_uri,
                                 headers=headers, method='POST',
                                 data=bytes(json.dumps(data).encode('utf-8')))
    try:
        with urllib.request.urlopen(req) as response:
            if response.code != 200:
                print("Trigger %s failed" % trigger.caption)
                return make_response(jsonify({"status": "failed", "trigger": trigger.id}), 200)
    except Exception as err:
        print(err)
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
            return redirect(url_for('admin_triggers'))
    elif request.method == 'POST':
        trigger_id = request.values.get('id')
        caption = request.values.get('caption')
        order = int(request.values.get('order'))
        trigger_json = json.loads(request.values.get('trigger_json'))
        include_user = True if request.values.get('include_user') else False
        webhook_uri = request.values.get('webhook_uri')
        password = request.values.get('password')
        trigger_json = json.dumps(trigger_json)
        if not trigger_id:
            trigger = Trigger(
                caption=caption,
                order=order,
                trigger_json=trigger_json,
                include_user=include_user,
                webhook_uri=webhook_uri,
                password=password
            )
            db.session.add(trigger)
            db.session.commit()
        else:
            if Trigger.query.get(int(trigger_id)):
                trigger = Trigger.query.get(int(trigger_id))
                trigger.caption = caption
                trigger.order = order
                trigger.trigger_json = trigger_json
                trigger.include_user = include_user
                trigger.webhook_uri = webhook_uri
                trigger.password = password
                db.session.add(trigger)
                db.session.commit()
            else:
                trigger = Trigger(
                    caption=caption,
                    order=order,
                    trigger_json=trigger_json,
                    include_user=include_user,
                    webhook_uri=webhook_uri,
                    password=password
                )
                db.session.add(trigger)
                db.session.commit()
    triggers = Trigger.query.all()
    return render_template('admin_triggers.html', triggers=triggers)


@app.route("/api/register/begin", methods=["POST"])
@login_required
def register_begin():
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
    if not Authenticator.query.all():
        abort(404)

    username = request.form.get('login_username')
    password = request.form.get('login_password')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not user.check_password(password):
        user.failed()
        add_to_ban(request.remote_addr)
        return make_response(jsonify({'fail': 'Wrong password'}), 401)

    authenticators = []
    for authenticator in Authenticator.query.filter_by(user=user.id):
        authenticators.append(AttestedCredentialData(authenticator.credential))
    if not authenticators:
        return make_response(jsonify({'fail': 'No authenticator enrolled'}), 401)
    auth_data, state = server.authenticate_begin(authenticators)
    session["state"] = state
    session["user_id"] = user.id
    
    return cbor.encode(auth_data)


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    if not Authenticator.query.all():
        abort(404)

    authenticators = []
    for authenticator in Authenticator.query.all():
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

    user = User.query.filter_by(id=int(session["user_id"])).first()
    login_user(user)

    user.sign_count = user.sign_count + 1
    user.failed_logins = 0
    user.last_failed = 0
    user.last_login = int(time.time())
    db.session.add(user)
    db.session.commit()
    banned = Banlist.query.filter_by(ip=request.remote_addr).first()
    if banned:
        banned.delete()
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

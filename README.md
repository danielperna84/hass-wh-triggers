# HASS-WH-Triggers

## Introduction

HASS-WH-Triggers is a [Flask](https://www.palletsprojects.com/p/flask/) webapp that allows you to store predefined triggers, which can be used to fire [Webhook trigger](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger) based automations in [Home Assistant](https://www.home-assistant.io/).  
Authentication is required to access the list of triggers. Logging in requires a registered username, password __and__ one of the following:
- A device to perform [FIDO2](https://fidoalliance.org/fido2/) / [WebAuthn](https://www.w3.org/TR/webauthn/) authentication. This could be a Security Key by e.g. [Yubico](https://www.yubico.com) (or other FIDO2 device vendors), Android 7+, [Windows Hello](https://www.microsoft.com/en-us/windows/windows-hello) or Apple’s Touch ID (currently only when using [Google Chrome](https://www.google.com/chrome/)). iOs devices with version 13+ support hardware tokens as well. More information on WebAuthn can be found [here](https://webauthn.guide/). You can test if your device is WebAuthn compatible at this site: https://webauthn.io/.
- An enrolled [TOTP](https://tools.ietf.org/html/rfc6238) token (the ones used with Google Authenticator ([Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2), [iOs](https://apps.apple.com/app/google-authenticator/id388497605)))
- A One-Time-Password sent to the user by the admin

## What do I use this for?

The purpose of this tool is to provide external access to specific Home Assistant automations without exposing Home Assistant itself / granting full access to users with less privileges. Currently Home Assistant has no concept of role based access from start to end. So whoever can login into Home Assistant can pretty much control everythig. By limiting the users access to a set of specific automations, you can provide restricted control for 3rd parties.  
Example: You have an automated door lock and want to grant access to your home to a sibling. You however don't want them to control anything else. Hence you (currently) can't solve this problem by adding a dedicated user in Home Assistant. There are solutions to this problem with a varying degree of usability, effort to set up, and most importantly: __security__.  
This webapp solves the problem by only providing predefined triggers (buttons) for webhook-based automations in a simple user interface. So in the example from above your sibling would only see the button _Unlock door_, but besides that have no other control over your environment.

## Security

The following steps have been taken to make this tool fairly safe to use:
- A valid username and password are required
- [2-Factor authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) is a strict requirement
- Registering a new user requires a manually created registration token
- Clients failing to authenticate / register will be banned after a configurable amount of failed attempts for a configurable amount of time
- No API-level access to Home Assistant is required (only the public, but secret, webhooks are called)
- Triggers can optionally be protected by their individual password / PIN

## How it works

Home Assistant provides [Webhook triggers](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger) to execute automations. These triggers can be fired from the internet without any authentication. By using a cryptic webbhook id it is pretty unlikely an attacker is able to execute the automation by guessing the webhook id.  
This tool leverages those triggers to execute automations _remotely_ (it can run on any server in the web that supports Flask apps). Within a trigger you specify the used webhook URI, JSON-data that should be included as a payload, optionally the name of the user that fires the trigger, and also optionally a password that is required to fire the selected trigger. The latter serves to configure multiple triggers, but only allowing certain triggers to be fired if the secret is known to the user.  
Because of the nature of webhook triggers your Home Assistant installation has to be exposed to the internet. Or at least the webhook part of it. You can configure to disable certificate checks when calling the webhooks if you are using self-signed certificates for Home Assistant. FIDO2 / WebAuthn (the token-part of the built-in security) does not work without certificates. So however you deploy the app, make sure it can be accessed using an encrypted connection.

## Operation

### User registration

When you first run this app and access it with your browser, you will automatically be redirected to an URI like this: `https://yourdomain.com/register/none`. This specific URI only works as long as no users are registered. The user you register as will become the administrator user. Choose a very secure password for this user. The next step will ask you to set up your 2-Factor authentication token. More information on this in the next section.  
Registration of additional users require a registration token, created by an user with administrator privileges. These tokens can be created in the _Admin_ menu at _Registration tokens_. Click the _Add token_ button. The page will refresh and display the created token. Click on the token to generate a registration-URI that you can send to users whom you want to grant access. Registration is only possible with a valid token. Attempts to register with invalid tokens result in IP banning after multiple failed attempts.

### After registration

Once a user is registered he is automatically logged in and redirected to the 2-Factor configuration. Without the second factor further logins are not possible. Hence this step should __not__ be skipped if the user should be able to log in without manually created OTPs.  
At the 2-Factor configuration you can set up either (multiple) FIDO2 / WebAuthn tokens or a single TOTP token. FIDO2 is recommended because it attaches authentication to a specific device. You can use TOTP as a fallback or alternative. But keep in mind that the _secrets_ used for TOTP can be enrolled on multiple devices or shared in other ways.

#### FIDO2

To enroll your FIDO2 token enter a name for it, then click _Add FIDO2 token_. Follow the instructions displayed by your browser to complete the enrollment process. If no errors occurred, the token will be added to the table above.

#### TOTP

If you choose to use TOTP, click the _Generate TOTP token_ button. You will be prompted to continue because this process will overwrite existing tokens from a previous enrollment (if you have added a TOTP token before). After confirming the prompt the page will refresh and you will see the _Base32 secret_ the TOTP will be derived from during authentication. Depending on your authenticator you now either have to enter the _Base32 secret_, or you can scan the QR Code displayed below. If you are doing this from a mobile device, tapping the QR Code should automatically add the token to your authenticator application. The QR Code is based on the _Provisioning URI_ you can find here as well. Use this URI if you want to create the QR Code manually.

## Automation in Home Assistant

This is a minimal automation in Home Assistant (YAML style) that will write a message to the logs at the `warning` level. It includes the trigger data, allowing you to observe what data arrives at Home Assistant after executing the trigger.

```yaml
automation old:
  trigger:
    platform: webhook
    webhook_id: secretwebhookid
  action:
    service: system_log.write
    data_template:
      message: "{{ trigger.json }}"
      level: warning
```

If you add a trigger with the trigger data `{"test": "foo"}` and check the _Include user_ checkbox, the output will look something like this:

```
2020-01-17 22:22:37 WARNING (MainThread) [homeassistant.components.system_log.external] {'test': 'foo', 'user': 'john.doe'}
```

## Installation (manual, for testing)

```bash
git clone https://github.com/danielperna84/hass-wh-triggers.git
cd hass-wh-triggers
python3 -m venv venv
source venv/bin/activate
cd hass_wh_triggers
pip install -r requirements
python create_db.py
# Locally for testing
python app.py
# On a publicly reachable server
RPID="yourdomain.com" ORIGIN="https://yourdomain.com:8443" flask run --host=0.0.0.0 --port=8443 --cert=/etc/pki/tls/certs/yourcert.pem --key=/etc/pki/tls/private/yourkey.key
```

This uses the integrated server of Flask to serve the webapp. It should __NOT__ be used for production use. Head over to the [Flask documentation](https://flask.palletsprojects.com/en/1.1.x/deploying/) for more information on how to properly serve Flask apps.

## Disclaimer

This app is in an early stage and should only be used with great caution. I am not responsible for any damage that might result out of using my work. Use at your own risk! I also have to mention, that this is my first Flask app. So I might be doing some pretty stupid stuff. Feel free to review my code and suggest improvements.

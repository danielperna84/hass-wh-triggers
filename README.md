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

Head over to the [wiki](https://github.com/danielperna84/hass-wh-triggers/wiki) for information on how to operate this tool.

## Installation (manual, for testing)

```bash
git clone https://github.com/danielperna84/hass-wh-triggers.git
cd hass-wh-triggers
python3 -m venv venv
source venv/bin/activate
cd hass_wh_triggers
pip install -r requirements
python create_db.py
# Testing has debug enabled. With debug enabled an extra DebugLogin button is visible which lets you login with just the username and password!
# Locally for testing
python app.py
# On a publicly reachable server
RPID="yourdomain.com" ORIGIN="https://yourdomain.com:8443" python app.py
```

This uses the integrated server of Flask to serve the webapp. It should __NOT__ be used for production use. Head over to the [Flask documentation](https://flask.palletsprojects.com/en/1.1.x/deploying/) for more information on how to properly serve Flask apps.

## Disclaimer

This app is in an early stage and should only be used with great caution. I am not responsible for any damage that might result out of using my work. Use at your own risk! I also have to mention, that this is my first Flask app. So I might be doing some pretty stupid stuff. Feel free to review my code and suggest improvements.

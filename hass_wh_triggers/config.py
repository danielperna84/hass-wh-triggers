"""App configuration."""
import os

class Config:
    """Set Flask configuration vars"""

    # General Config
    sk = os.environ.get('SECRET_KEY')
    SECRET_KEY = sk if sk else os.urandom(40)
    FLASK_ENV = os.environ.get('FLASK_ENV')

    # App specifiv
    RP_ID = os.environ.get('RPID') if os.environ.get('RPID') else 'localhost'
    ORIGIN = os.environ.get('ORIGIN') if os.environ.get('ORIGIN') else 'https://localhost:5000'

    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.db'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    if RP_ID != 'localhost':
        SERVER_NAME = ORIGIN.split('/')[-1]
        SESSION_COOKIE_SECURE = True

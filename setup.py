"""A setuptools based setup module."""
from os import path
from setuptools import setup, find_packages
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='hass-wh-triggers',
    version='0.0.1',
    description='HASS-WH-Triggers',
    long_description=long_description,
    url='https://github.com/danielperna84/hass-wh-triggers',
    author='Daniel Perna',
    author_email='danielperna84@gmail.com',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3.7',
    ],
    keywords='Home Assistant FIDO2 WebAuthn TOTP',
    packages=find_packages(),
    install_requires=[
        "cbor2==4.1.2",
        "cryptography",
        "Flask",
        "Flask-Login",
        "Flask-SQLAlchemy",
        "Flask-WTF",
        "future",
        "pyotp",
        "pyOpenSSL",
        "setuptools",
        "setuptools-scm",
        "six",
        "SQLAlchemy",
        "WTForms",
    ],
    entry_points={
        'console_scripts': [
            'init-db = hass_wh_triggers.create_db:main',
            'hass-wh-triggers = hass_wh_triggers.app:main',
        ],
    },
    include_package_data=True,
    data_files=[]
)

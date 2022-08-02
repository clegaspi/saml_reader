#!/usr/bin/env python

from setuptools import setup, find_packages
from saml_reader import __version__

setup(
      name='saml_reader',
      version=__version__,
      description='SAML response parser for MongoDB Cloud',
      author='Christian Legaspi',
      author_email='christian.legaspi@mongodb.com',
      url='https://github.com/clegaspi/saml_reader',
      packages=find_packages(),
      entry_points={
            "console_scripts": [
                  "saml_reader=saml_reader.cli:start_saml_reader",
                  "saml_web_app=saml_reader.web.cli_hook:start_web_app_from_cli"
            ]},
      install_requires=[
            'pyperclip',
            'haralyzer',
            'python3-saml',
            'cryptography',
            'networkx',
            'lxml',     # This should be installed as part of python3-saml
            'defusedxml',      # This should be installed as part of python3-saml
            'dash>=2.6,<2.7',      # For web interface
            'dash-extensions>=0.1.0,<0.2.0'
      ]
)

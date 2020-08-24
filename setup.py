#!/usr/bin/env python

from setuptools import setup

setup(
      name='saml_reader',
      version='0.0.2a',
      description='SAML response parser for MongoDB Cloud',
      author='Christian Legaspi',
      author_email='christian.legaspi@mongodb.com',
      url='https://github.com/clegaspi/saml_reader',
      packages=['saml_reader'],
      entry_points={"console_scripts": ["saml_reader=saml_reader.cli:cli"]},
      install_requires=[
            'pyperclip',
            'haralyzer',
            'python3-saml',
            'cryptography',
      ]
)

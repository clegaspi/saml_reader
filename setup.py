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
      entry_points={"console_scripts": ["saml_reader=saml_reader.cli:start_saml_reader"]},
      install_requires=[
            'pyperclip',
            'haralyzer',
            'python3-saml',
            'cryptography'
      ]
)

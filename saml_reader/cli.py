import sys

import pyperclip
import argparse

from saml_reader.cert import Certificate
from saml_reader.saml import SamlParser, SamlResponseEncryptedError
from saml_reader.har import HarParser

__version__ = "0.0.0a4"

REQUIRED_ATTRIBUTES = {'firstName', 'lastName', 'email'}
VALID_INPUT_TYPES = {'base64', 'xml', 'har'}


def read_file(filename):
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Cannot find file specified: {filename}")
    return data


def read_clipboard():
    data = pyperclip.paste()
    return data


def read_stdin():
    data = "".join(sys.stdin.readlines())
    return data


def parse_raw_data(input_type, data):
    if input_type == 'base64':
        return SamlParser(data)
    if input_type == 'xml':
        return SamlParser.from_xml(data)
    if input_type == 'har':
        return SamlParser(HarParser(data).parse())
    raise ValueError(f"Invalid data type specified: {input_type}")


def parse(source, input_type, filename=None):
    input_type = input_type.lower()
    if input_type not in VALID_INPUT_TYPES:
        raise ValueError(f"Invalid input type: {input_type}")

    if source == 'clip':
        raw_data = read_clipboard()
    elif source == 'stdin':
        raw_data = read_stdin()
    elif source == 'file':
        raw_data = read_file(filename)
    else:
        raise ValueError(f"Invalid source: {source}")

    try:
        saml = parse_raw_data(input_type, raw_data)
    except SamlResponseEncryptedError:
        print("SAML response is encrypted. Cannot parse.\n"
              "Advise customer to update their identity provider "
              "to send an unencrypted SAML response.")
        return

    try:
        cert = Certificate(saml.get_certificate())
    except ValueError:
        print("Could not locate certificate. Identity provider info will not be available.")
        cert = None
    display(saml, cert)


def display(saml, cert):
    print(f"SAML READER")
    print(f"----------------------")
    if cert is not None:
        print(f"IDENTITY PROVIDER "
              f"(from certificate):"
              f"\n{cert.get_organization_name() or cert.get_common_name()}")
        print("---")
    print(f"ISSUER URI:"
          f"\n{saml.get_issuers()[0]}")
    print("---")
    print(f"AUDIENCE URI:"
          f"\n{saml.get_audiences()[0]}")
    print("---")
    print(f"ASSERTION CONSUMER SERVICE URL:"
          f"\n{saml.get_acs()}")
    print("---")
    print(f"NAME ID:"
          f"\nValue (this should be an e-mail): {saml.get_subject_nameid()}"
          f"\nFormat (this should end in 'unspecified' or 'emailAddress'): "
          f"{saml.get_subject_nameid_format()}")
    print("---")
    print(f"ATTRIBUTES:")
    req_attribs_in_assertion = set()
    for name, value in saml.get_attributes().items():
        print(f"Name: {name}")
        print(f"Value: {value[0]}")
        print("-")
        if name in REQUIRED_ATTRIBUTES:
            req_attribs_in_assertion.add(name)

    if len(req_attribs_in_assertion) != len(REQUIRED_ATTRIBUTES):
        print(f"This SAML response is missing the following required attribute(s), "
              f"or they are spelled incorrectly:")
        for attribute in REQUIRED_ATTRIBUTES - req_attribs_in_assertion:
            print(attribute)


def cli():
    parser = argparse.ArgumentParser(prog="SAML Reader",
                                     description='Read a SAML response and pull out '
                                                 'relevant values for diagnosing '
                                                 'federated authentication issues.')
    parser.add_argument('filepath', metavar="PATH", action='store',
                        default=None, nargs='?',
                        help='path for source file. If omitted, '
                             'input is assumed from stdin unless --clip is specified')
    parser.add_argument('--stdin',
                        dest='stdin', action='store_true', required=False,
                        help='read data from stdin (this is default if not specified)')
    parser.add_argument('--clip',
                        dest='clip', action='store_true', required=False,
                        help='read data from system clipboard')
    parser.add_argument('--type',
                        dest='input_type', action='store', required=False,
                        choices=['xml', 'base64', 'har'], default='xml',
                        help='type of data being read in (default: xml)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    parsed_args = parser.parse_args(sys.argv[1:])

    source = 'stdin'
    filename = None
    if parsed_args.filepath is None:
        if parsed_args.clip:
            source = 'clip'
    else:
        source = 'file'
        filename = parsed_args.filepath

    parse(source, parsed_args.input_type, filename=filename)


if __name__ == '__main__':
    cli()

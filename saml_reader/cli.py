import sys
import os

import pyperclip
import argparse

from saml_reader.cert import Certificate
from saml_reader.saml import SamlParser
from saml_reader.har import HarParser


REQUIRED_ATTRIBUTES = {'firstName', 'lastName', 'email'}
VALID_INPUT_TYPES = {'base64', 'xml', 'har'}


def read_file(input_type, filename):
    with open(filename, 'r') as f:
        data = f.read()
    return parse_raw_data(input_type, data)


def read_clipboard(input_type='base64'):
    data = pyperclip.paste()
    return parse_raw_data(input_type, data)


def read_stdin(input_type='base64'):
    data = sys.stdin.read()
    return parse_raw_data(input_type, data)


def parse_raw_data(input_type, data):
    if input_type == 'base64':
        return SamlParser(data)
    if input_type == 'xml':
        return SamlParser.from_xml(data)
    if input_type == 'har':
        return SamlParser(HarParser(data).parse())
    raise ValueError(f"Invalid data type specified: {input_type}")


def main(source, input_type):
    input_type = input_type.lower()
    if input_type not in VALID_INPUT_TYPES:
        raise ValueError(f"Invalid input type: {input_type}")

    if source == 'clip':
        saml = read_clipboard(input_type)
    elif source == 'stdin':
        saml = read_stdin(input_type)
    elif os.path.exists(source):
        saml = read_file(input_type, source)
    else:
        raise ValueError(f"Invalid source: {source}")

    cert = Certificate(saml.get_certificate())
    display(saml, cert)


def display(saml, cert):
    print(f"SAML READER")
    print(f"----------------------")
    print(f"IDENTITY PROVIDER "
          f"(if this is the customer's company, it may be on-prem ADFS):"
          f"\n{cert.get_organization_name()}")
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
          f"\nFormat (this should contain 'Unspecified' or 'Email'): "
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
    parser.add_argument('--version', action='version', version='%(prog)s 0.0.1')
    parser.add_argument('source', metavar="<stdin, clip, PATH>", action='store',
                        type=str,
                        help='where to read data from.\n'
                             'stdin (default): read from pipe\n'
                             'clip: read from system clipboard\n'
                             'PATH: read from file specified by PATH'
                        )
    parser.add_argument('--type',
                        dest='input_type', action='store', required=False,
                        choices=['xml', 'base64', 'har'], default='xml',
                        help='type of data being read in (default: xml)')

    parsed_args = parser.parse_args(sys.argv[1:])
    main(parsed_args.source, parsed_args.input_type)


if __name__ == '__main__':
    cli()

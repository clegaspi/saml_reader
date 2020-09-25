"""
Command line interface for SAML Reader parser. This is where MongoDB Cloud-specific
interpretation of the SAML data is done and returned to the user.

Attributes:
    VALID_INPUT_TYPES (set): set of strings of the valid input types for this tool
"""
import sys
import json
import re

import pyperclip
import argparse

from saml_reader.cert import Certificate
from saml_reader.saml import SamlParser, SamlResponseEncryptedError
from saml_reader.har import HarParser
from saml_reader import __version__
from saml_reader.mongo import MongoFederationConfig, MongoVerifier


VALID_INPUT_TYPES = {'base64', 'xml', 'har'}


def read_file(filename):
    """
    Reads data from a file

    Args:
        filename (basestring): path of file to read

    Returns:
        (basestring) contents of file

    Raises:
        (FileNotFoundError) if the file does not exist or cannot be read
    """
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Cannot find file specified: {filename}")
    return data


def read_clipboard():
    """
    Reads data from the system clipboard

    Returns:
        (basestring) contents of clipboard
    """
    data = pyperclip.paste()
    return data


def read_stdin():
    """
    Reads contents of stdin (standard in) to get piped data

    Returns:
        (basestring) concatenated contents of stdin
    """
    data = "".join(sys.stdin.readlines())
    return data


def parse_raw_data(input_type, data):
    """
    Parse various data types to return SAML response

    Args:
        input_type (basestring): data type of `data`, must be
            `'base64'`, `'xml'`, or `'har'`
        data (basestring): data to parse for SAML response

    Returns:
        (SamlParser) Object containing SAML data

    Raises:
        (ValueError) if an invalid `input_type` is specified
    """
    if input_type == 'base64':
        return SamlParser(data)
    if input_type == 'xml':
        return SamlParser.from_xml(data)
    if input_type == 'har':
        return SamlParser(HarParser(data).parse())
    raise ValueError(f"Invalid data type specified: {input_type}")


def parse_saml_data(source, input_type, filename=None):
    """
    Parses input for SAML response and displays summary and analysis

    Args:
        source (basestring): type of input to read, must be one of:
            - `'clip'`: read from the system clipboard
            - `'file'`: read from a file, must specify path in `'filename'`
            - `'stdin'`: read from pipe via stdin (standard in)
        input_type (basestring): data type of `data`, must be
            `'base64'`, `'xml'`, or `'har'`
        filename (basestring, Optional): path of file to read, only required
            if `source` is `'file'`

    Returns:
        None

    Raises:
        (ValueError) if the `source` or the `input_type` is invalid
    """
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
        return None, None

    if not saml.validate_num_assertions():
        if bytes("AuthnRequest", "utf-8") in saml.response:
            print("The input data appears to be a SAML request instead of a SAML response.\n"
                  "Please ask the customer for the SAML response instead of the request.")
        else:
            print("The SAML data does not contain any response data.")
        return None, None

    try:
        cert = Certificate(saml.get_certificate())
    except ValueError:
        print("Could not locate certificate. Identity provider info will not be available.")
        cert = None

    return saml, cert


def display_validation_results(verifier):
    """
    Display MongoDB Cloud-specific recommendations for identifiable issues
    with the SAML data.

    Args:
        verifier (MongoVerifier): SAML and cert data

    Returns:
        None
    """
    error_messages = verifier.get_error_messages()
    if not error_messages:
        print("No errors found! :)")
        print("------------")
        return

    print("-----MONGODB CLOUD VERIFICATION-----")
    for msg in error_messages:
        print(f"\n{msg}\n------")


def display_summary(verifier):
    """
    Display summary of parsed SAML data

    Args:
        verifier (MongoVerifier): SAML and cert data

    Returns:
        None
    """

    print("-----SAML SUMMARY-----")

    if verifier.has_certificate():
        print(f"IDENTITY PROVIDER "
              f"(from certificate):"
              f"\n{verifier.get_identity_provider()}")
        print("---")
    print(f"ISSUER URI:"
          f"\n{verifier.get_issuer()}")
    print("---")
    print(f"AUDIENCE URI:"
          f"\n{verifier.get_audience_uri()}")
    print("---")
    print(f"ASSERTION CONSUMER SERVICE URL:"
          f"\n{verifier.get_assertion_consumer_service_url()}")
    print("---")
    print(f"ENCRYPTION ALGORITHM:"
          f"\n{verifier.get_encryption_algorithm().upper()}")
    print("---")
    print(f"NAME ID:"
          f"\nValue: {verifier.get_name_id() or '(this value is missing)'}"
          f"\nFormat: {verifier.get_name_id_format() or '(this value is missing)'}")
    print("---")

    # Checking for the required attributes for MongoDB Cloud
    print(f"ATTRIBUTES:")
    for name, value in verifier.get_claim_attributes().items():
        print(f"Name: {name}")
        print(f"Value: {value}")
        print("-")


def cli():
    """
    Entrypoint for the command line interface. Handles parsing command line arguments.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(prog="SAML Reader",
                                     description='Read a SAML response and pull out '
                                                 'relevant values for diagnosing '
                                                 'federated authentication issues.')
    # TODO: Look into having argparse verify if the path is valid
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
    parser.add_argument('--compare',
                        dest='compare', action='store', required=False,
                        nargs='*',
                        help='enter values for comparison (no args = prompt, 1 arg = JSON file)')
    parser.add_argument('--summary',
                        dest='summary', action='store_true', required=False,
                        help='displays full summary of the parsed SAML data')
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

    print(f"SAML READER")
    print(f"----------------------")

    federation_config = None
    if parsed_args.compare is not None:
        if len(parsed_args.compare) == 0:
            federation_config = prompt_for_comparison_values()
        else:
            federation_config = parse_comparison_values_from_json(parsed_args.compare[0])

    saml, cert = parse_saml_data(source, parsed_args.input_type, filename=filename)

    if not saml:
        return

    verifier = MongoVerifier(saml, cert, comparison_values=federation_config)
    verifier.validate_configuration()

    display_validation_results(verifier)
    if parsed_args.summary:
        display_summary(verifier)


def prompt_for_comparison_values():
    federation_config = MongoFederationConfig()
    print("Please enter the following values for comparison with\n"
          "values in the SAML response. Press Return to skip a value.")
    federation_config.set_value('firstName',
                                input("Customer First Name: ") or None)
    federation_config.set_value('lastName',
                                input("Customer Last Name: ") or None)
    federation_config.set_value('email',
                                input("Customer Email Address: ") or None)
    federation_config.set_value('issuer',
                                input("IdP Issuer URI: ") or None)
    federation_config.set_value('acs',
                                input("Assertion Consumer Service URL: ") or None)
    federation_config.set_value('audience',
                                input("Audience URI: ") or None)
    encryption = None
    while not encryption:
        encryption_string = input("Encryption Algorithm (""SHA1"" or ""SHA256""): ")
        if encryption_string == "":
            break
        encryption = re.findall(r'(?i)SHA-?(1|256)', encryption_string)
        if not encryption:
            print("Invalid encryption value. Must be ""SHA1"" or ""SHA256""")
        else:
            # This is meant to convert "sha-256" to "SHA256" for consistency
            encryption = encryption[0].upper().replace("-", "")
    federation_config.set_value('encryption', encryption)
    print("------------")

    return federation_config


def parse_comparison_values_from_json(filename):
    with open(filename, 'r') as f:
        comparison_values = json.load(f)

    if 'encryption' in comparison_values:
        # This is meant to convert "sha-256" to "SHA256" for consistency
        comparison_values['encryption'] = comparison_values['encryption'].upper().replace("-", "")
    federation_config = MongoFederationConfig(**comparison_values)
    return federation_config


if __name__ == '__main__':
    cli()

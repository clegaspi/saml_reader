"""
Command line interface for SAML Reader parser. These functions handle all
user interaction/display.
"""
import sys
import json
import re

import argparse

from saml_reader.parser import Parser
from saml_reader.mongo import MongoFederationConfig, MongoVerifier
from saml_reader import __version__


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
    print(f"Parsing SAML data...")

    # Parse saml data before prompting for input values to not risk clipboard being erased
    saml_parser = Parser(source, parsed_args.input_type, filename=filename)

    if not saml_parser.cert_is_valid():
        for msg in saml_parser.get_errors():
            print(msg)

        if not saml_parser.saml_is_valid():
            return

    print(f"Done")

    federation_config = None
    if parsed_args.compare is not None:
        if len(parsed_args.compare) == 0:
            federation_config = prompt_for_comparison_values()
        else:
            print("Parsing comparison values...")
            federation_config = parse_comparison_values_from_json(parsed_args.compare[0])
            print("Done")

    verifier = MongoVerifier(saml_parser.get_saml(),
                             saml_parser.get_certificate(),
                             comparison_values=federation_config)
    verifier.validate_configuration()
    display_validation_results(verifier)
    if parsed_args.summary:
        display_summary(verifier)


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

    print("\n-----SAML SUMMARY-----")

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

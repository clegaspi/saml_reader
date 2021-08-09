"""
Command line interface for SAML Reader parser. These functions handle display.
User inputs are handled elsewhere.
"""
import sys
import json
import argparse

from saml_reader.text_reader import TextReader
from saml_reader.validation.mongo import MongoSamlValidator
from saml_reader.validation.input_validation import MongoFederationConfig, MongoComparisonValue
from saml_reader.saml.parser import DataTypeInvalid
from saml_reader import __version__


def cli(cl_args):
    """
    Entrypoint for the command line interface. Handles parsing command line arguments.

    Args:
        cl_args (iterable): Command-line arguments. Possibilities:
            - `<filepath>`: positional argument. Path to input file. If omitted,
                data will be read in from stdin unless `--clip` is specified.
            - `--stdin`: optional argument. Specifying will read data from stdin.
            - `--clip`: optional argument. Specifying will read data from clipboard
            - `--type <type>`: optional argument, default: 'xml'. Specifies the data type
                to be read in. Must be one of: 'xml', 'base64', 'har'
            - `--compare <file, optional>`: optional argument. Compare SAML data vs. data entered
                by user. If no file is specified, application will prompt for values. If file
                specified, must be JSON file which contains only attribute keys found in
                `UserInputValidation`
            - `--summary`: optional argument. Will output a summary of relevant
                data read from SAML response.
            - `--summary-only`: optional argument. Only outputs summary info, does not perform
                MongoDB Cloud tests
            - `--version`: optional argument. Displays version information and exits.
            - `--help`: optional argument. Displays help information and exits.

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
    parser.add_argument('--summary-only',
                        dest='summary_only', action='store_true', required=False,
                        help='do not run MongoDB-specific validation, only output summary')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')
    # TODO: Add XML pretty print option
    parsed_args = parser.parse_args(cl_args)

    if parsed_args.summary_only and parsed_args.compare is not None:
        print("ERROR: Cannot specify --compare and --summary-only")
        return

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
    try:
        saml_parser = TextReader(
            source, parsed_args.input_type, filename=filename)
    except DataTypeInvalid:
        if parsed_args.input_type == 'har':
            print("We could not find the correct data in the HAR data specified.\n"
                  "Check to make sure that the input data is of the correct type.")
        else:
            print(f"The input data does not appear to be the specified input type '{parsed_args.input_type}'.\n"
                  f"Check to make sure that the input data is of the correct type.")
        return

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
            try:
                federation_config = parse_comparison_values_from_json(
                    parsed_args.compare[0])
            except ValueError as e:
                if len(e.args) > 1:
                    print(f"Attribute '{e.args[1]}' in the provided JSON did not pass validation")
                    return
                raise e
            print("Done")

    print("------------")
    validator = MongoSamlValidator(saml_parser.get_saml(),
                                   saml_parser.get_certificate(),
                                   comparison_values=federation_config)

    if not parsed_args.summary_only:
        validator.validate_configuration()
        display_validation_results(validator)

    if parsed_args.summary or parsed_args.summary_only:
        display_summary(validator)


def display_validation_results(validator):
    """
    Display MongoDB Cloud-specific recommendations for identifiable issues
    with the SAML data.

    Args:
        validator (MongoSamlValidator): SAML and cert data

    Returns:
        None
    """
    error_messages = validator.get_error_messages()
    if not error_messages:
        print("No errors found! :)")
        print("------------")
        return

    print("-----MONGODB CLOUD VERIFICATION-----")
    for msg in error_messages:
        print(f"\n{msg}\n------")


def display_summary(validator):
    """
    Display summary of parsed SAML data

    Args:
        validator (MongoSamlValidator): SAML and cert data

    Returns:
        None
    """

    print("\n-----SAML SUMMARY-----")

    if validator.has_certificate():
        print(f"IDENTITY PROVIDER "
              f"(from certificate):"
              f"\n{validator.get_identity_provider()}")
        print("---")
        print(f"SIGNING CERTIFICATE EXPIRATION DATE (MM/DD/YYYY):"
              f"\n{validator.get_certificate().get_expiration_date():%m/%d/%Y}")
        print("---")
    print(f"ASSERTION CONSUMER SERVICE URL:"
          f"\n{validator.get_assertion_consumer_service_url() or '(this value is missing)'}")
    print("---")
    print(f"AUDIENCE URL:"
          f"\n{validator.get_audience_url() or '(this value is missing)'}")
    print("---")
    print(f"ISSUER URI:"
          f"\n{validator.get_issuer() or '(this value is missing)'}")
    print("---")
    print(f"ENCRYPTION ALGORITHM:"
          f"\n{validator.get_encryption_algorithm() or '(this value is missing)'}")
    print("---")
    print(f"NAME ID:"
          f"\nValue: {validator.get_name_id() or '(this value is missing)'}"
          f"\nFormat: {validator.get_name_id_format() or '(this value is missing)'}")
    print("---")
    # Checking for the required attributes for MongoDB Cloud
    print(f"ATTRIBUTES:")
    if not validator.get_claim_attributes():
        print("No claim attributes found")
    else:
        for name, value in validator.get_claim_attributes().items():
            print(f"Name: {name}")
            if isinstance(value, list):
                print("Values:")
                for v in value:
                    print(f"- {v}")
            else:
                print(f"Value: {value}")
            print("--")


def prompt_for_comparison_values():
    """
    Prompt user to enter values for comparing with the SAML response data

    Returns:
        (MongoFederationConfig) object containing validated comparison values
    """
    federation_config = MongoFederationConfig()
    print("Please enter the following values for comparison with\n"
          "values in the SAML response. Press Return to skip a value.")

    comparison_values = [
        MongoComparisonValue(
            'firstName', "Customer First Name:", multi_value=False),
        MongoComparisonValue(
            'lastName', "Customer Last Name:", multi_value=False),
        MongoComparisonValue(
            'email', "Customer Email Address:", multi_value=False),
        MongoComparisonValue(
            'acs', "MongoDB Assertion Consumer Service URL:", multi_value=False),
        MongoComparisonValue(
            'audience', "MongoDB Audience URL:", multi_value=False),
        MongoComparisonValue(
            'domains', "Domain(s) associated with IdP:", multi_value=True),
        MongoComparisonValue('issuer', "IdP Issuer URI:", multi_value=False),
        MongoComparisonValue(
            'cert_expiration', "Signing Certificate Expiration Date (MM/DD/YYYY):", multi_value=False),
        MongoComparisonValue(
            'encryption', "Encryption Algorithm (""SHA1"" or ""SHA256""):", multi_value=False),
        MongoComparisonValue('role_mapping_expected', "Is customer expecting role mapping (y/N):",
                             multi_value=False, default="N")
    ]

    for value in comparison_values:
        value.prompt_for_user_input()
        if not value.is_null():
            federation_config.set_value(value)

    if federation_config.get_parsed_value('role_mapping_expected'):
        member_of = MongoComparisonValue(
            'memberOf',
            "Expected role mapping group names (if unknown, leave blank):",
            multi_value=True
        )
        member_of.prompt_for_user_input()

        if not member_of.is_null():
            federation_config.set_value(
                member_of.get_name(),
                member_of.get_value()
            )

    print("------------")

    return federation_config


def parse_comparison_values_from_json(filename):
    """
    Read comparison values from JSON file and validate

    Args:
        filename (basestring): path to JSON-formatted file with comparison values
            See `UserInputValidation` for valid fields.

    Returns:
        (MongoFederationConfig) object containing validated comparison values
    """
    with open(filename, 'r') as f:
        comparison_values = json.load(f)
    federation_config = MongoFederationConfig(**comparison_values)
    return federation_config


def start_saml_reader():
    # This is the CLI hook in setup.py
    cli(sys.argv[1:])


if __name__ == '__main__':
    start_saml_reader()

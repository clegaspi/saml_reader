"""
Command line interface for SAML Reader parser. These functions handle display.
User inputs are handled elsewhere.
"""
import sys
import os
import json
from functools import partial
from io import StringIO

import argparse

from saml_reader.text_reader import TextReader
from saml_reader.validation.mongo import MongoSamlValidator
from saml_reader.validation.input_validation import MongoFederationConfig, MongoComparisonValue
from saml_reader.saml.parser import DataTypeInvalid
# from saml_reader.saml.errors import SamlError
from saml_reader import __version__


class OutputStream(StringIO):
    """Emulates printing to stdout, but instead capturing data as a `StringIO`-like object.
    """
    def print(self, data):
        """Emulates the `print()` function for stdout.

        Args:
            data (Any): any object that implements `__str__()`
        """
        self.write(data + '\n')


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
    filepath = None
    if parsed_args.filepath is None:
        if parsed_args.clip:
            source = 'clip'
    else:
        source = 'file'
        filepath = parsed_args.filepath

    compare = False
    compare_file = None
    if parsed_args.compare is not None:
        compare = True
        if len(parsed_args.compare) > 0:
            compare_file = parsed_args.compare[0]

    run_analysis(
        input_type=parsed_args.input_type,
        source=source,
        filepath=filepath,
        compare=compare,
        compare_file=compare_file,
        print_analysis=not parsed_args.summary_only,
        print_summary=parsed_args.summary or parsed_args.summary_only
    )


def run_analysis(
        input_type='xml', source='clip', filepath=None, raw_data=None,
        compare=False, compare_file=None, compare_object=None,
        print_analysis=True, print_summary=True, output_stream=print, input_stream=input):
    """Interface to run SAML Reader analysis backend.

    Args:
        input_type (basestring, optional): Data type to be analyzed. Options are:
            - `"xml"`: SAML dat as a decoded XML file. This is the default.
            - `"base64"`: SAML data encoded as base64. This should be non-percent-encoded.
            - `"har"`: SAML data contained in a har dump file. This should contain only one SAML response.
        source (basestring, optional): Where to read the data from. Options are:
            - `"clip"`: From the system clipboard. This is the default.
            - `"stdin"`: From the stdin.
            - `"file"`: From a file. Requires `filepath` be a valid path to a file.
            - `"raw"`: From raw data sent to the function. Requires `raw_data` be valid SAML data.
        filepath (basestring, optional): Path to the file to be read in. Requires `source='file'`.
        raw_data (basestring, optional): Raw data to be parsed. Requires `source='raw'`.
        compare (bool, optional): Whether to perform input comparison to SAML data. Defaults to False.
        compare_file (basestring, optional): An input JSON file with comparison values. Requires `compare=True`.
            Takes precendence over `compare_object`.
        compare_object (MongoFederationConfig, optional): Comparison values as MongoFederationConfig object.
        print_analysis (bool, optional): Prints the analysis to `output_stream`. Defaults to True.
        print_summary (bool, optional): Prints the SAML data summary to `output_stream`. Defaults to True.
        output_stream (function, optional): A function which takes one argument to ingest data output by this analysis.
            Defaults to native `print` function.
        input_stream (function, optional): A function which takes one argument (a prompt) and returns one argument
            (a basestring) containing a user's answer to the prompt. Defaults to native `input` function.
    """

    output_stream(f"SAML READER")
    output_stream(f"----------------------")
    output_stream(f"Parsing SAML data...")

    try:
        saml_data = parse_saml_data(input_type=input_type, source=source,
                                    filepath=filepath, raw_data=raw_data)
    except DataTypeInvalid:
        if input_type == 'har':
            output_stream("We could not find the correct data in the HAR data specified.\n"
                          "Check to make sure that the input data is of the correct type.")
        else:
            output_stream(f"The input data does not appear to be the specified input type '{input_type}'.\n"
                          f"Check to make sure that the input data is of the correct type.")
        return

    for msg in saml_data.get_errors():
        output_stream(msg)

    if not saml_data.saml_is_valid():
        return

    output_stream(f"Done")

    federation_config = None
    if compare:
        if compare_file:
            output_stream("Parsing comparison values...")
            try:
                federation_config = parse_comparison_values_from_json(compare_file)
            except ValueError as e:
                if len(e.args) > 1:
                    # TODO: This could probably use a custom exception
                    output_stream(f"Attribute '{e.args[1]}' in the provided JSON did not pass validation")
                    return
                raise e
            output_stream("Done")
        elif compare_object:
            federation_config = compare_object
        else:
            federation_config = prompt_for_comparison_values(output_stream=output_stream,
                                                             input_stream=input_stream)

    output_stream("------------")
    validator = MongoSamlValidator(saml_data.get_saml(),
                             saml_data.get_certificate(),
                             comparison_values=federation_config)

    if print_analysis:
        validator.validate_configuration()
        validation_report = compile_validation_report(validator)
        output_stream(validation_report)

    if print_summary:
        summary = compile_summary(validator)
        output_stream(summary)


def parse_saml_data(input_type='xml', source='clip', filepath=None, raw_data=None):
    """Reading in and parsing SAML data.

    Args:
        input_type (basestring, optional): Data type to be analyzed. Options are:
            - `"xml"`: SAML dat as a decoded XML file. This is the default.
            - `"base64"`: SAML data encoded as base64. This should be non-percent-encoded.
            - `"har"`: SAML data contained in a har dump file. This should contain only one SAML response.
        source (basestring, optional): Where to read the data from. Options are:
            - `"clip"`: From the system clipboard. This is the default.
            - `"stdin"`: From the stdin.
            - `"file"`: From a file. Requires `filepath` be a valid path to a file.
            - `"raw"`: From raw data sent to the function. Requires `raw_data` be valid SAML data.
        filepath (basestring, optional): Path to the file to be read in. Requires `source='file'`.
        raw_data (basestring, optional): Raw data to be parsed. Requires `source='raw'`.

    Raises:
        ValueError: If an invalid combination of options is specified.

    Returns:
        BaseSamlParser: parsed SAML data object
    """
    # Parse saml data before prompting for input values to not risk clipboard being erased
    constructor_func = None
    if source == 'stdin':
        constructor_func = TextReader.from_stdin
    elif source == 'clip':
        constructor_func = TextReader.from_clipboard
    elif source == 'file':
        if filepath and os.path.exists(filepath):
            constructor_func = partial(TextReader.from_file, filename=filepath)
    elif source == 'raw' and raw_data:
        constructor_func = partial(TextReader, raw_data=raw_data)
    else:
        raise ValueError(f"Invalid input type specified: {source}")

    return constructor_func(input_type)


def compile_validation_report(validator):
    """
    Display MongoDB Cloud-specific recommendations for identifiable issues
    with the SAML data.

    Args:
        validator (MongoSamlValidator): SAML and cert data

    Returns:
        None
    """

    out = OutputStream()
    output_stream = out.print

    error_messages = validator.get_error_messages()
    if not error_messages:
        output_stream("No errors found! :)")
        output_stream("------------")
    else:
        output_stream("-----MONGODB CLOUD VERIFICATION-----")
        for msg in error_messages:
            output_stream(f"\n{msg}\n------")

    return out.getvalue()


def compile_summary(validator):
    """
    Display summary of parsed SAML data

    Args:
        validator (MongoSamlValidator): SAML and cert data

    Returns:
        None
    """

    out = OutputStream()
    output_stream = out.print

    output_stream("\n-----SAML SUMMARY-----")

    if validator.has_certificate():
        output_stream(f"IDENTITY PROVIDER "
                      f"(from certificate):"
                      f"\n{validator.get_identity_provider()}")
        output_stream("---")
        output_stream(f"SIGNING CERTIFICATE EXPIRATION DATE (MM/DD/YYYY):"
              f"\n{validator.get_certificate().get_expiration_date():%m/%d/%Y}")
        output_stream("---")
    output_stream(f"ASSERTION CONSUMER SERVICE URL:"
                  f"\n{validator.get_assertion_consumer_service_url() or '(this value is missing)'}")
    output_stream("---")
    output_stream(f"AUDIENCE URL:"
                  f"\n{validator.get_audience_url() or '(this value is missing)'}")
    output_stream("---")
    output_stream(f"ISSUER URI:"
                  f"\n{validator.get_issuer() or '(this value is missing)'}")
    output_stream("---")
    output_stream(f"ENCRYPTION ALGORITHM:"
                  f"\n{validator.get_encryption_algorithm() or '(this value is missing)'}")
    output_stream("---")
    output_stream(f"NAME ID:"
                  f"\nValue: {validator.get_name_id() or '(this value is missing)'}"
                  f"\nFormat: {validator.get_name_id_format() or '(this value is missing)'}")
    output_stream("---")
    # Checking for the required attributes for MongoDB Cloud
    output_stream(f"ATTRIBUTES:")
    if not validator.get_claim_attributes():
        output_stream("No claim attributes found")
    else:
        duplicate_attributes = validator.get_duplicate_attribute_names()
        for name, value in validator.get_claim_attributes().items():
            output_stream(f"Name: {name}")
            output_stream(f"Is Duplicated: {'YES' if name in duplicate_attributes else 'No'}")
            if isinstance(value, list):
                output_stream("Values:")
                for v in value:
                    output_stream(f"- {v}")
            else:
                output_stream(f"Value: {value}")
            output_stream("--")

    return out.getvalue()


def prompt_for_comparison_values(output_stream=print, input_stream=input):
    """
    Prompt user to enter values for comparing with the SAML response data

    Args:
        output_stream (function, optional): A function which takes one argument to ingest data output by this analysis.
            Defaults to native `print` function.
        input_stream (function, optional): A function which takes one argument (a prompt) and returns one argument
            (a basestring) containing a user's answer to the prompt. Defaults to native `input` function.
    Returns:
        (MongoFederationConfig) object containing validated comparison values
    """
    federation_config = MongoFederationConfig()
    output_stream("Please enter the following values for comparison with\n"
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
        value.prompt_for_user_input(output_stream=output_stream, input_stream=input_stream)
        if not value.is_null():
            federation_config.set_value(value)

    if federation_config.get_parsed_value('role_mapping_expected'):
        member_of = MongoComparisonValue(
            'memberOf',
            "Expected role mapping group names (if unknown, leave blank):",
            multi_value=True
        )
        member_of.prompt_for_user_input(output_stream=output_stream, input_stream=input_stream)

        if not member_of.is_null():
            federation_config.set_value(member_of)

    output_stream("------------")

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
    """CLI hook that reads args from system
    """
    # This is the CLI hook in setup.py
    cli(sys.argv[1:])


if __name__ == '__main__':
    # Can start the CLI with this file
    start_saml_reader()

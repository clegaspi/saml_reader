"""
Command line interface for SAML Reader parser. This is where MongoDB Cloud-specific
interpretation of the SAML data is done and returned to the user.

Attributes:
    REQUIRED_ATTRIBUTES (set): set of strings of the required Atlas attributes in the
        SAML response
    VALID_INPUT_TYPES (set): set of strings of the valid input types for this tool
"""
import sys

import pyperclip
import argparse

from saml_reader.cert import Certificate
from saml_reader.saml import SamlParser, SamlResponseEncryptedError
from saml_reader.har import HarParser
from saml_reader import __version__


REQUIRED_ATTRIBUTES = {'firstName', 'lastName', 'email'}
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


def parse(source, input_type, filename=None):
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
        return

    if not saml.validate_num_assertions():
        if bytes("AuthnRequest", "utf-8") in saml.response:
            print("The input data appears to be a SAML request instead of a SAML response.\n"
                  "Please ask the customer for the SAML response instead of the request.")
        else:
            print("The SAML data does not contain any response data.")
        return

    try:
        # TODO: Maybe move this to the display() section or wherever it ends up in a refactor
        cert = Certificate(saml.get_certificate())
    except ValueError:
        print("Could not locate certificate. Identity provider info will not be available.")
        cert = None
    display(saml, cert)


def display(saml, cert):
    """
    Display parsed SAML data and MongoDB Cloud-specific recommendations for identifiable issues
    with the SAML data.

    Args:
        saml (SamlParser): SAML data
        cert (Certificate, NoneType): Certificate data. Can be `None` if no certificate info is
            available in the SAML response

    Returns:
        None
    """

    # TODO: It might be nice to abstract this into separate functions or a class
    #       to put all of the MongoDB Cloud-specific analysis in one place
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

    # Checking for the required attributes for MongoDB Cloud
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

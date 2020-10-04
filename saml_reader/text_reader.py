"""
This class handles reading in raw text to be prepped for interpretation by other classes
"""
import sys

import pyperclip

from saml_reader.cert import Certificate
from saml_reader.saml.parser import RegexSamlParser, StandardSamlParser
from saml_reader.saml.parser import SamlResponseEncryptedError, SamlParsingError
from saml_reader.har import HarParser


class TextReader:
    """
    Parses raw SAML and certificate data from various input sources

    Attributes:
        VALID_INPUT_TYPES (set): set of strings of the valid input types for this tool
    """

    VALID_INPUT_TYPES = {'base64', 'xml', 'har'}

    def __init__(self, source, input_type, filename=None):
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

        self._errors = []

        input_type = input_type.lower()
        if input_type not in self.VALID_INPUT_TYPES:
            raise ValueError(f"Invalid input type: {input_type}")

        if source == 'clip':
            raw_data = self._read_clipboard()
        elif source == 'stdin':
            raw_data = self._read_stdin()
        elif source == 'file':
            raw_data = self._read_file(filename)
        else:
            raise ValueError(f"Invalid source: {source}")

        self._valid_saml = True
        used_regex_parser = False
        try:
            self._saml = self._parse_raw_data(input_type, raw_data)
        except SamlResponseEncryptedError:
            self._errors.append(
                "SAML response is encrypted. Cannot parse.\n"
                "Advise customer to update their identity provider "
                "to send an unencrypted SAML response."
            )
            self._saml = None
            self._valid_saml = False
        except SamlParsingError:
            self._errors.append("WARNING: XML parsing failed. Using fallback regex parser.\n"
                                "Some values may not be able to be parsed.")
            used_regex_parser = True
            self._saml = self._parse_raw_data(input_type, raw_data,
                                              parser=RegexSamlParser)

        if self._valid_saml:
            if not used_regex_parser and not self._saml.is_assertion_found():
                if self._saml.is_saml_request():
                    self._errors.append(
                        "The input data appears to be a SAML request instead of a SAML response.\n"
                        "Please ask the customer for the SAML response instead of the request."
                    )
                else:
                    self._errors.append("The SAML data does not contain any response data.")
                self._valid_saml = False

        self._valid_cert = False
        self._cert = None
        if self._valid_saml:
            try:
                self._cert = Certificate(self._saml.get_certificate())
            except ValueError:
                self._errors.append(
                    "Could not locate certificate. Identity provider info will not be available."
                )
            self._valid_cert = self._cert is not None

    @staticmethod
    def _read_file(filename):
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

    @staticmethod
    def _read_clipboard():
        """
        Reads data from the system clipboard

        Returns:
            (basestring) contents of clipboard
        """
        data = pyperclip.paste()
        return data

    @staticmethod
    def _read_stdin():
        """
        Reads contents of stdin (standard in) to get piped data

        Returns:
            (basestring) concatenated contents of stdin
        """
        data = "".join(sys.stdin.readlines())
        return data

    @staticmethod
    def _parse_raw_data(input_type, data, parser=StandardSamlParser):
        """
        Parse various data types to return SAML response

        Args:
            input_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`
            data (basestring): data to parse for SAML response
            parser (BaseSamlParser): parser class. Default: StandardSamlParser

        Returns:
            (SamlParser) Object containing SAML data

        Raises:
            (ValueError) if an invalid `input_type` is specified
        """
        if input_type == 'base64':
            return parser(data)
        if input_type == 'xml':
            return parser.from_xml(data)
        if input_type == 'har':
            return parser(HarParser(data).parse())
        raise ValueError(f"Invalid data type specified: {input_type}")

    def get_saml(self):
        """
        Gets parsed SAML object

        Returns:
            (SamlParser) Object containing SAML data. Returns None if the SAML
                data could not be parsed because it was encrypted
        """
        return self._saml

    def get_certificate(self):
        """
        Gets certificate object

        Returns:
            (Certificate) Object containing certificate data. Returns None if
                certificate could not be parsed from SAML data
        """
        return self._cert

    def saml_is_valid(self):
        """
        Indicates if SAML response was successfully parsed

        Returns:
            (bool) True if the SAML response was successfully parsed, False otherwise.
                Call `Parser.get_errors()` to see errors.
        """
        return self._valid_saml

    def cert_is_valid(self):
        """
        Indicates if certificate was successfully parsed

        Returns:
            (bool) True if the certificate was successfully parsed, False otherwise.
                Call `Parser.get_errors()` to see errors.
        """
        return self._valid_cert

    def get_errors(self):
        """
        Returns errors encountered during parsing process.

        Returns:
            (`list` of `basestring`) If there were errors, will contain text explaining
                errors. Empty list if no errors were encountered.
        """

        return self._errors

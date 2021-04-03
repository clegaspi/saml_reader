"""
This class handles reading in raw text to be prepped for interpretation by other classes
"""
import sys

import pyperclip

from saml_reader.cert import Certificate
from saml_reader.saml.parser import RegexSamlParser, StandardSamlParser
from saml_reader.saml.errors import SamlParsingError, SamlResponseEncryptedError, IsASamlRequest, DataTypeInvalid
from saml_reader.har import HarParser, HarParsingError, NoSAMLResponseFound


class TextReader:
    """
    Parses raw SAML and certificate data from various input sources

    Attributes:
        VALID_INPUT_TYPES (set): set of strings of the valid input types for this tool
    """

    VALID_INPUT_TYPES = {'base64', 'xml', 'har'}

    def __init__(self, input_type, raw_data):
        """
        Parses input for SAML response and displays summary and analysis

        Args:
            input_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`
            raw_data (basestring): raw data to be parsed for SAML data

        Returns:
            None

        Raises:
            (DataTypeInvalid) if the `input_type` is invalid
        """

        self._errors = []

        input_type = input_type.lower()
        if input_type not in self.VALID_INPUT_TYPES:
            raise DataTypeInvalid(f"Invalid input type: {input_type}")

        self._valid_cert = False
        self._cert = None
        self._saml = None
        self._valid_saml = True
        self._parser_used = 'strict'
        is_encrypted = False
        is_a_response = False

        try:
            self._saml = self._parse_raw_data(input_type, raw_data)
            if self._saml.used_relaxed_parser():
                self._parser_used = 'relaxed'
        except SamlParsingError:
            self._parser_used = 'regex'
        except SamlResponseEncryptedError as e:
            is_encrypted = True
            self._valid_saml = False
            self._parser_used = e.parser
        except IsASamlRequest as e:
            is_a_response = True
            self._valid_saml = False
            self._parser_used = e.parser
        except NoSAMLResponseFound:
            self._valid_saml = False
            self._errors.append("Could not find a SAML response in the HAR data.\n"
                                "Please verify the input type and data is correct.")
            return

        if self._parser_used == 'regex':
            try:
                self._saml = self._parse_raw_data(input_type, raw_data,
                                                  parser=RegexSamlParser)
            except SamlResponseEncryptedError:
                is_encrypted = True
                self._saml = None
                self._valid_saml = False
            except IsASamlRequest:
                is_a_response = True
                self._saml = None
                self._valid_saml = False

        if self._parser_used != 'strict':
            self._errors.append(f"WARNING: XML parsing failed. Using fallback '{self._parser_used}' parser. "
                                f"Some values may not parse correctly.\n")

        if is_encrypted:
            self._errors.append(
                "SAML response is encrypted. Cannot parse.\n"
                "Advise customer to update their identity provider "
                "to send an unencrypted SAML response."
            )
            return

        if is_a_response:
            self._errors.append(
                "The input data appears to be a SAML request instead of a SAML response.\n"
                "Please ask the customer for the SAML response instead of the request."
            )
            return

        if not self._saml.found_any_values():
            self._errors.append(
                "Could not parse any relevant information from the input data.\n"
                "Please make sure that your input contains SAML data."
            )
            self._valid_saml = False

        if self._valid_saml:
            raw_cert = self._saml.get_certificate()

            self._cert = None
            if raw_cert:
                try:
                    self._cert = Certificate(raw_cert)
                except ValueError as e:
                    if not e.args[0].startswith("Unable to load certificate"):
                        raise e

            if not self._cert:
                self._errors.append(
                    "Could not locate certificate. Identity provider info will not be available."
                )
            self._valid_cert = self._cert is not None

    @classmethod
    def from_clipboard(cls, data_type):
        """
        Read data from the clipboard.
        Args:
            data_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`

        Returns:
            (TextReader) parsed SAML data
        """
        raw_data = cls._read_clipboard()
        return cls(data_type, raw_data)

    @classmethod
    def from_stdin(cls, data_type):
        """
        Read data from the stdin.
        Args:
            data_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`

        Returns:
            (TextReader) parsed SAML data
        """
        raw_data = cls._read_stdin()
        return cls(data_type, raw_data)

    @classmethod
    def from_file(cls, data_type, filename):
        """
        Read data from the clipboard.
        Args:
            data_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`
            filename (basestring): path to file

        Returns:
            (TextReader) parsed SAML data
        """
        raw_data = cls._read_file(filename)
        return cls(data_type, raw_data)

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

    def _parse_raw_data(self, input_type, data, parser=StandardSamlParser):
        """
        Parse various data types to return SAML response

        Args:
            input_type (basestring): data type of `data`, must be
                `'base64'`, `'xml'`, or `'har'`
            data (basestring): data to parse for SAML response
            parser (BaseSamlParser): parser class. Default: StandardSamlParser

        Returns:
            (BaseSamlParser) Object containing SAML data

        Raises:
            (DataTypeInvalid) if an invalid `input_type` is specified
        """
        if input_type == 'base64':
            return parser.from_base64(data)
        if input_type == 'xml':
            return parser.from_xml(data)
        if input_type == 'har':
            try:
                # TODO: Do the HAR parsing in the constructor?
                har_parser = HarParser(data)
                data = har_parser.parse()
            except HarParsingError as e:
                raise DataTypeInvalid(*e.args)
            self._errors.extend(har_parser.errors)
            return parser.from_base64(data)
        raise DataTypeInvalid(f"Invalid data type specified: {input_type}")

    def get_saml(self):
        """
        Gets parsed SAML object

        Returns:
            (BaseSamlParser) Object containing SAML data. Returns None if the SAML
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

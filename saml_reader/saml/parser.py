"""
This module implements features related to parsing the actual SAML response data
and pulling specific pieces of information from the contents of the response document.

In large part, the functionality builds on the python3-saml package produced by OneLogin.
"""

import re

from onelogin.saml2.utils import OneLogin_Saml2_Utils as utils
from urllib.parse import unquote
from lxml import etree

from saml_reader.saml.base import BaseSamlParser
from saml_reader.saml.oli import OLISamlParser
from saml_reader.saml.errors import SamlResponseEncryptedError, IsASamlRequest, DataTypeInvalid


class StandardSamlParser(BaseSamlParser):
    """
    Wrapper around OneLogin SAML response parser, adding functionality to
    grab fields other than what is supported by default.
    """

    def __init__(self, response):
        """
        Parses SAML response from XML input.

        Args:
            response (basestring): SAML response as a stringified XML document

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        self._saml = OLISamlParser(response)
        self._saml_values = dict()
        super().__init__()
        self._parse_saml_values()

    def used_relaxed_parser(self):
        """
        Determine if the parser had to fall back on an XML parser that
        attempts to correct syntax errors. If the relaxed parser was used,
        may indicate there were errors in the SAML response data (did you copy-paste
        correctly?)

        Returns:
            (bool) True if we used the syntax-correcting parser,
                False for standard, strict parser
        """
        return self._saml.used_relaxed_parser

    def _parse_saml_values(self):
        """
        Pre-parse SAML values and cache them

        Returns:
            None
        """

        value_by_field = {
            'certificate': self.__get_certificate(),
            'name_id': self._saml.query_assertion(
                '/saml:Subject/saml:NameID'
            ),
            'name_id_format': self._saml.query_assertion(
                '/saml:Subject/saml:NameID'
            ),
            'acs': self.__get_acs(),
            'encryption':
                self._saml.query_assertion('/ds:Signature/ds:SignedInfo/ds:SignatureMethod') or
                self._saml.query('/samlp:Response/ds:Signature/ds:SignedInfo/ds:SignatureMethod'),
            'audience': self._saml.query_assertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience'),
            'issuer': self._saml.query_assertion('/saml:Issuer'),
            'attributes': self._saml.get_attributes()
        }

        transform_by_field = {
            'certificate': lambda x: x,
            'name_id': lambda x: x[0].text if x else None,
            'name_id_format': lambda x: x[0].attrib.get('Format') if x else None,
            'acs': lambda x: x,
            'encryption': self.__parse_encryption,
            'audience': lambda x: x[0].text if x else None,
            'issuer': lambda x: x[0].text if x else None,
            'attributes': self.__parse_attributes
        }

        for field, value in value_by_field.items():
            self._saml_values[field] = transform_by_field[field](value)

    def __get_acs(self):
        """
        Return the Assertion Consumer Service URL, if it exists in the SAML data

        Returns:
            (`basestring` or `None`) ACS data, or None, if it doesn't exist
        """
        value = self._saml.query('/samlp:Response')
        if value:
            return value[0].attrib.get('Destination')
        value = self._saml.query_assertion(
            '/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData'
        )
        if value:
            return value[0].attrib.get('Recipient')
        return None

    def __get_certificate(self):
        """
        Return the certificate data, if it exists in the SAML data

        Returns:
            (`basestring` or `None`) Certificate data, or None, if it doesn't exist
        """
        value = self._saml.query_assertion('/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate') or \
            self._saml.query('/samlp:Response/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
        if not value:
            return None
        return value[0].text

    @staticmethod
    def __parse_attributes(attribute_data):
        """
        Apply specific transformations to claim attributes.

        Args:
            attribute_data (dict): attribute data from SAML response

        Returns:
            (dict) transformed attributes
        """
        if not attribute_data:
            return None

        special_transform_by_attribute = {
            'memberOf': lambda x: x if x else []     # Retain list type for memberOf
        }

        transformed_attributes = dict()

        for attribute_name, value in attribute_data.items():
            if attribute_name in special_transform_by_attribute:
                transformed_attributes[attribute_name] = special_transform_by_attribute[attribute_name](value)
            else:
                transformed_attributes[attribute_name] = value[0] if value else ""

        return transformed_attributes

    @staticmethod
    def __parse_encryption(result):
        """
        Parse encryption values from URI
        Args:
            result (lxml.etree.Element): signature method query result

        Returns:
            (basestring) encryption algorithm, None if not found
        """
        if not result:
            return None
        uri = result[0].attrib.get('Algorithm') or ""
        algorithm = re.findall(r"(?i)sha(1|256)$", uri)
        if algorithm:
            return "SHA" + algorithm[0]
        return None

    @classmethod
    def from_xml(cls, xml):
        """
        Instantiates the class using XML input.

        Args:
            xml (basestring): SAML response as stringified XML document

        Returns:
            (BaseSamlParser) parsed SAML response object
        """
        rx = r'[<>]'
        if not re.search(rx, xml):
            raise DataTypeInvalid("This does not appear to be XML")
        return cls(xml)

    @classmethod
    def from_base64(cls, base64, url_decode=False):
        """
        Instantiates the class using base64-encoded XML input.

        Args:
            base64 (basestring): SAML response as base64-encoded XML string
            url_decode (bool): True performs url decoding before parsing. Default: False.

        Returns:
            (BaseSamlParser) parsed SAML response object
        """
        value = base64 if not url_decode else unquote(base64)
        # Strip whitespace
        value = re.sub(r'\s+', '', value)

        # Check to see if this is valid base64
        rx = r'[^a-zA-Z0-9/+=]'
        if re.search(rx, value):
            raise DataTypeInvalid("This does not appear to be valid base64")
        return cls(utils.b64decode(value))

    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string, None if value not found
        """
        return self._saml_values.get('certificate')

    def get_subject_name_id(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID, None if value not found
        """
        return self._saml_values.get('name_id')

    def get_subject_name_id_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID format, None if value not found
        """
        return self._saml_values.get('name_id_format')

    def get_assertion_consumer_service_url(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL, None if value not found
        """
        return self._saml_values.get('acs')

    def get_encryption_algorithm(self):
        """
        Retrieves the encryption algorithm used for certificate. Should be
        "sha1" or "sha256".

        Returns:
            (basestring) Value of encryption algorithm, None if value not found
        """
        return self._saml_values.get('encryption')

    def get_audience_url(self):
        """
        Retrieves the service provider's Audience URL.

        Returns:
            (basestring) Value of Audience URL, None if value not found
        """
        return self._saml_values.get('audience')

    def get_issuer_uri(self):
        """
        Retrieves the identity provider's Issuer URI.

        Returns:
            (basestring) Value of Issuer URI, None if value not found
        """
        return self._saml_values.get('issuer')

    def get_attributes(self):
        """
        Retrieves the identity provider's claim attributes.

        Returns:
            (dict) Claim attribute values keyed by attribute name, empty dict if no attributes were found
        """
        return self._saml_values.get('attributes') or dict()

    def is_assertion_found(self):
        """
        Checks if the response contains exactly one assertion.

        Returns:
            (bool): True if the response contains one assertion, False otherwise
        """
        return self._saml.validate_num_assertions()

    def get_xml(self, pretty=False):
        """
        Return raw XML of SAML response

        Args:
            pretty (bool): Pretty-prints XML if True. False is XML in one line.
                Default: False.

        Returns:
            (basestring) SAML response as XML string
        """
        if pretty:
            try:
                pretty_xml = etree.tostring(self._saml.document, pretty_print=True)
                return str(pretty_xml)
            except etree.XMLSyntaxError:
                raise ValueError("Cannot pretty print")
        return str(self._saml.response)

    def found_any_values(self):
        """
        Checks to see if we were able to parse any values at all

        Returns:
            (bool) True if any values were able to be parsed, False otherwise
        """
        return any(self._saml_values.values())


class RegexSamlParser(BaseSamlParser):
    """
    SAML parser which will be a little more forgiving to XML syntax errors by
    relying on regex instead of an XML parser
    """

    def __init__(self, response):
        """
        Parses SAML response from XML input.

        Args:
            response (basestring): SAML response as stringified XML document

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        self._saml = str(response)
        self._saml_values = dict()

        if self._is_encrypted():
            raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key", 'regex')
        if self._is_saml_request():
            raise IsASamlRequest("The SAML data contains a request and not a response", 'regex')

        super().__init__()
        self._parse_saml_values()

    def _parse_saml_values(self):
        """
        Pre-parse SAML values and cache them

        Returns:
            None
        """
        regex_by_field = {
            'certificate': re.compile(r"(?s)<(?:ds:)?X509Certificate.*?>(.*?)</(?:ds:)?X509Certificate>"),
            'name_id': re.compile(r"(?s)<(?:saml.?:)?NameID.*?>(.*?)</(?:saml.?:)?NameID>"),
            'name_id_format': re.compile(r"(?s)<(?:saml.?:)?NameID.*?Format=\"(.+?)\".*?>"),
            # This is a pretty relaxed regex because it occurs right at the beginning of the
            # SAML response where there could be syntax errors if someone copy-pasted poorly
            'acs': re.compile(r"(?s)(?:<saml.*?:Response)?.*?Destination=\"(.+?)\".*?>"),
            'encryption': re.compile(r"(?s)<(?:ds:)?SignatureMethod.*?Algorithm=\".+?sha(1|256)\".*?>"),
            'audience': re.compile(r"(?s)<(?:saml.?:)?Audience(?:\s.*?>|>)(.*?)</(?:saml.?:)?Audience>"),
            'issuer': re.compile(r"(?s)<(?:saml.?:)?Issuer.*?>(.*?)<\/(?:saml.?:)?Issuer>"),
            'attributes': re.compile(
                r"(?s)<(?:saml.?:)?Attribute.*?Name=\"(.+?)\".*?>\s*(.*?)\s*</(?:saml.?:)?Attribute>"
            )
        }

        transform_by_field = {
            'certificate': lambda x: x[0] if x else None,
            'name_id': lambda x: x[0] if x else None,
            'name_id_format': lambda x: x[0] if x else None,
            'acs': lambda x: x[0] if x else None,
            'encryption': lambda x: "SHA" + x[0] if x else None,
            'audience': lambda x: x[0] if x else None,
            'issuer': lambda x: x[0] if x else None,
            'attributes': self.__transform_attributes
        }

        for field, regex in regex_by_field.items():
            result = regex.findall(self._saml)
            result = transform_by_field[field](result)
            self._saml_values[field] = result

    @staticmethod
    def __transform_attributes(raw_data):
        """
        Apply specific transformations to claim attributes.

        Args:
            raw_data (dict): attribute data from SAML response

        Returns:
            (dict) transformed attributes
        """
        if not raw_data:
            return None
        value_regex = re.compile(r"(?s)<(?:saml.?:)?AttributeValue.*?>(.*?)</(?:saml.?:)?AttributeValue>")

        attributes_to_return_as_list = {'memberOf'}

        transformed_attributes = dict()
        for name, value in raw_data:
            value = value_regex.findall(value)
            if not value:
                # findall() returns a list with an empty string if there was a match but the group was empty
                # but returns an empty list if there were no matches
                value = ['(could not parse)']
            transformed_attributes[name] = value[0] if name not in attributes_to_return_as_list else value

        return transformed_attributes

    def _is_encrypted(self):
        """
        Determines if the SAML response is encrypted.

        Returns:
            (bool) True if encrypted, False otherwise
        """
        rx = r"(?s)<\/?(?:saml.?:)?EncryptedAssertion"
        result = re.findall(rx, self._saml)

        return bool(result)

    def _is_saml_request(self):
        """
        Determines if received SAML data is actually a SAML request instead of response

        Returns:
            (bool) True if it is a request, False otherwise
        """
        rx = r"<\/?(?:saml.{0,2}:)?AuthnRequest"
        result = re.findall(rx, self._saml)

        return bool(result)

    @classmethod
    def from_xml(cls, xml):
        """
        Instantiates the class using XML input.

        Args:
            xml (basestring): SAML response as stringified XML document

        Returns:
            (BaseSamlParser) parsed SAML response object
        """
        # Check to see if this couldn't be XML
        rx = r'[<>]'
        if not re.search(rx, xml):
            raise DataTypeInvalid("This does not appear to be XML")
        return cls(xml)

    @classmethod
    def from_base64(cls, base64, url_decode=False):
        """
        Instantiates the class using base64-encoded XML input.

        Args:
            base64 (basestring): SAML response as base64-encoded XML string
            url_decode (bool): True performs url decoding before parsing. Default: False.

        Returns:
            (BaseSamlParser) parsed SAML response object
        """

        value = base64 if not url_decode else unquote(base64)
        # Strip whitespace
        value = re.sub(r'\s+', '', value)

        # Check to see if this is valid base64
        rx = r'[^a-zA-Z0-9/?=]'
        if re.search(rx, value):
            raise DataTypeInvalid("This does not appear to be valid base64")
        return cls(utils.b64decode(value))

    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string, None if value not found
        """

        return self._saml_values.get('certificate')

    def get_subject_name_id(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID, None if value not found
        """
        return self._saml_values.get('name_id')

    def get_subject_name_id_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID, None if value not found
        """
        return self._saml_values.get('name_id_format')

    def get_assertion_consumer_service_url(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL, None if value not found
        """
        return self._saml_values.get('acs')

    def get_encryption_algorithm(self):
        """
        Retrieves the encryption algorithm used for certificate. Should be
        "sha1" or "sha256".

        Returns:
            (basestring) Value of encryption algorithm, None if value not found
        """
        return self._saml_values.get('encryption')

    def get_audience_url(self):
        """
        Retrieves the service provider's Audience URL.

        Returns:
            (basestring) Value of Audience URL algorithm, None if value not found
        """
        return self._saml_values.get('audience')

    def get_issuer_uri(self):
        """
        Retrieves the identity provider's Issuer URI.

        Returns:
            (basestring) Value of Issuer URI, None if value not found
        """
        return self._saml_values.get('issuer')

    def get_attributes(self):
        """
        Retrieves the identity provider's claim attributes.

        Returns:
            (dict) Claim attribute values keyed by attribute name, empty dict if no values found
        """
        return self._saml_values.get('attributes') or dict()

    def is_assertion_found(self):
        """
        Checks if the response contains exactly one assertion.

        Returns:
            (bool): True if the response contains one assertion, False otherwise
        """
        rx = r"(?s)<(?:saml.?:)?Assertion.*?ID=\"(.+?)\".*?>"

        result = re.findall(rx, self._saml)
        return len(result) == 1

    def get_xml(self, pretty=False):
        """
        Return raw XML of SAML response

        Args:
            pretty (bool): Pretty-prints XML if True. False is XML in one line.
                Default: False.

        Returns:
            (basestring) SAML response as XML string
        """
        raw_xml = self._saml
        if pretty:
            # If we had to rely on this parser, there's not an easy way to
            # pretty-print this badly-formed XML
            return raw_xml
        return raw_xml

    def found_any_values(self):
        """
        Checks to see if we were able to parse any values at all

        Returns:
            (bool) True if any values were able to be parsed, False otherwise
        """
        return any(self._saml_values.values())

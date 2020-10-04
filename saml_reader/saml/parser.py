"""
This module implements features related to parsing the actual SAML response data
and pulling specific pieces of information from the contents of the response document.

In large part, the functionality builds on the python3-saml package produced by OneLogin.
"""

import re
from functools import partial

from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.utils import OneLogin_Saml2_Utils as utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from urllib.parse import unquote
from lxml import etree
from defusedxml.lxml import RestrictedElement

from saml_reader.saml.base import BaseSamlParser


class SamlResponseEncryptedError(Exception):
    """
    Custom exception type raised when SAML responses are encrypted
    """
    pass


class SamlParsingError(Exception):
    """
    Custom exception type raised when SAML response could not be parsed by this parser
    """
    pass


class StandardSamlParser(BaseSamlParser):
    """
    Wrapper around OneLogin SAML response parser, adding functionality to
    grab fields other than what is supported by default.
    """

    class _OLISamlParser(OneLogin_Saml2_Response):
        def __init__(self, response):
            # This is basically a copy-paste of the parent class __init__()
            # with tweaks to handle the change in parser, etc.

            # These are copied from the parent class
            self.__error = None
            self.decrypted_document = None
            self.encrypted = None
            self.valid_scd_not_on_or_after = None

            # After this point, the logic is customized
            self.__settings = None
            self.response = response
            self.document = None
            self._used_relaxed_parser = False
            while self.document is None:
                try:
                    self.document = OneLogin_Saml2_XML.to_etree(self.response)
                except etree.XMLSyntaxError:
                    # Use a parser which attempts to recover bad XML
                    relaxed_xml_parser = etree.XMLParser(recover=False, resolve_entities=False)
                    lookup = etree.ElementDefaultClassLookup(element=RestrictedElement)
                    relaxed_xml_parser.set_element_class_lookup(lookup)
                    # Inject parser into the OLI class because there is no provided way to
                    # change parser
                    OneLogin_Saml2_XML._parse_etree = partial(OneLogin_Saml2_XML._parse_etree,
                                                              parser=relaxed_xml_parser)
                    self._used_relaxed_parser = True
                except AttributeError as e:
                    if e.args[0].endswith("'getroottree'"):
                        # Even the relaxed parser couldn't parse this. Parser fails.
                        raise SamlParsingError("Could not parse the XML data")
                    else:
                        raise e
                except Exception as e:
                    raise e

            if self._used_relaxed_parser:
                # If the parser was relaxed, want to make sure we brute-force check.
                encrypted_assertion_nodes = re.findall(r'</?EncryptedAssertion', self.response)
            else:
                encrypted_assertion_nodes = self.query('/samlp:Response/saml:EncryptedAssertion')
            if encrypted_assertion_nodes:
                raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key")

        def query_assertion(self, path):
            return self.__query_assertion(path)

        def query(self, path):
            return self.__query(path)

    def __init__(self, response):
        """
        Parses SAML response from XML input.

        Args:
            response (basestring): SAML response as a stringified XML document

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        self._saml = self._OLISamlParser(response)
        super().__init__()

    @classmethod
    def from_xml(cls, xml):
        """
        Instantiates the class using XML input.

        Args:
            xml (basestring): SAML response as stringified XML document

        Returns:
            (SamlParser) parsed SAML response object
        """
        # This just re-encodes the XML as base64 before passing it into constructor
        return cls(xml)

    @classmethod
    def from_base64(cls, base64, url_decode=False):
        """
        Instantiates the class using base64-encoded XML input.

        Args:
            base64 (basestring): SAML response as base64-encoded XML string
            url_decode (bool): True performs url decoding before parsing. Default: False.

        Returns:
            (SamlParser) parsed SAML response object
        """

        return cls(utils.b64decode(base64 if not url_decode else unquote(base64)))

    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string
        Raises:
            (ValueError) Raised when the certificate entry is not found in the data
        """
        result = self._saml.query_assertion(
            '/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
        if result:
            return result[0].text
        # TODO: Maybe change these functions to return none instead of failing hard
        raise ValueError("Did not find certificate")

    def get_subject_name_id(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        result = self._saml.query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            return result[0].text
        raise ValueError("Did not find Name ID")

    def get_subject_name_id_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        result = self._saml.query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            # TODO: Change to .get('Format') if changing function to soft fail
            return result[0].attrib['Format']
        raise ValueError("Did not find Name ID Format")

    def get_assertion_consumer_service_url(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL
        Raises:
            (ValueError) Raised when the Assertion Consumer Service
             entry is not found in the data
        """
        result = self._saml.query(
            '/samlp:Response')
        if result:
            # TODO: Change to .get('Destination') if changing function to soft fail
            return result[0].attrib['Destination']
        raise ValueError("Did not find ACS")

    def get_encryption_algorithm(self):
        """
        Retrieves the encryption algorithm used for certificate. Should be
        "sha1" or "sha256".

        Returns:
            (basestring) Value of encryption algorithm
        Raises:
            (ValueError) Raised when the encryption algorithm
             entry is not found in the data
        """
        result = self._saml.query_assertion(
            '/ds:Signature/ds:SignedInfo/ds:SignatureMethod')

        # If the encryption algorithm isn't in the specific assertion, check the outer section
        if not result:
            result = self._saml.query(
                '/samlp:Response/ds:Signature/ds:SignedInfo/ds:SignatureMethod')

        if result:
            # TODO: Change to .get('Algorithm') if changing function to soft fail
            algorithm_uri = result[0].attrib['Algorithm']
            algorithm = re.findall(r"sha(1|256)", algorithm_uri)
            if not algorithm:
                return ValueError(f"Unexpected algorithm value: {algorithm_uri}")
            return "SHA" + algorithm[0]
        raise ValueError("Did not find algorithm value")

    def get_audience_url(self):
        """
        Retrieves the service provider's Audience URL.

        Returns:
            (basestring) Value of Audience URL algorithm
        Raises:
            (ValueError) Raised when the Audience URL
             entry is not found in the data
        """
        audiences = self._saml.get_audiences()
        if audiences:
            return audiences[0]
        raise ValueError("Audience URL not found")

    def get_issuer_uri(self):
        """
        Retrieves the identity provider's Issuer URI.

        Returns:
            (basestring) Value of Issuer URI
        Raises:
            (ValueError) Raised when the Issuer URI
             entry is not found in the data
        """
        issuers = self._saml.get_issuers()
        if issuers:
            return issuers[0]
        raise ValueError("Issuer URI not found")

    def get_attributes(self):
        """
        Retrieves the identity provider's claim attributes.

        Returns:
            (dict) Claim attribute values keyed by attribute name
        Raises:
            (ValueError) Raised when the attributes
             are not found in the data
        """
        attribs = self._saml.get_attributes()
        if not attribs:
            raise ValueError("Attributes not found")
        return {k: v[0] if v else "" for k, v in attribs.items()}

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
                return pretty_xml
            except etree.XMLSyntaxError:
                raise ValueError("Cannot pretty print")
        return self._saml.response

    def is_saml_request(self):
        """
        Determines if received SAML data is actually a SAML request instead of response

        Returns:
            (bool) True if it is a request, False otherwise
        """
        return bytes("AuthnRequest", 'utf-8') in self.get_xml()


class RegexSamlParser(BaseSamlParser):
    """
    SAML parser which will be a little more forgiving to XML syntax errors by
    relying on regex instead of an XML parser
    """

    def __init__(self, response, url_decode=False):
        """
        Parses SAML response from XML input.

        Args:
            response (basestring): SAML response as stringified XML document

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        self._saml = str(response)

        if self.is_encrypted():
            raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key")

        super().__init__()

    def is_encrypted(self):
        """
        Determines if the SAML response is encrypted.

        Returns:
            (bool) True if encrypted, False otherwise
        """
        rx = r"(?s)<\/?EncryptedAssertion"
        result = re.findall(rx, self._saml)

        return bool(result)

    @classmethod
    def from_xml(cls, xml):
        """
        Instantiates the class using XML input.

        Args:
            xml (basestring): SAML response as stringified XML document

        Returns:
            (SamlParser) parsed SAML response object
        """
        # This just re-encodes the XML as base64 before passing it into constructor
        return cls(utils.b64encode(xml))

    @classmethod
    def from_base64(cls, base64, url_decode=False):
        """
        Instantiates the class using base64-encoded XML input.

        Args:
            base64 (basestring): SAML response as base64-encoded XML string
            url_decode (bool): True performs url decoding before parsing. Default: False.

        Returns:
            (SamlParser) parsed SAML response object
        """

        return cls(utils.b64decode(base64 if not url_decode else unquote(base64)))

    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string
        Raises:
            (ValueError) Raised when the certificate entry is not found in the data
        """

        rx = r"(?s)<(?:ds:)?X509Certificate.*?>(.*?)<\/(?:ds:)?X509Certificate>"

        result = re.findall(rx, self._saml)

        if result:
            return result[0]
        # TODO: Maybe change these functions to return none instead of failing hard
        raise ValueError("Did not find certificate")

    def get_subject_name_id(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        rx = r"(?s)<(?:saml.?:)?NameID.*?>(.*?)<\/(?:saml.?:)?NameID>"

        result = re.findall(rx, self._saml)

        if result:
            return result[0]
        raise ValueError("Did not find Name ID")

    def get_subject_name_id_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        rx = r"(?s)<(?:saml.?:)?NameID.*?Format=\"(.+?)\".*?>"

        result = re.findall(rx, self._saml)
        if result:
            return result[0]
        raise ValueError("Did not find Name ID Format")

    def get_assertion_consumer_service_url(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL
        Raises:
            (ValueError) Raised when the Assertion Consumer Service
             entry is not found in the data
        """
        # This is a pretty relaxed regex because it occurs right at the beginning of the
        # SAML response where there could be syntax errors if someone copy-pasted poorly
        rx = r"(?s)(?:<saml.*?:Response)?.*?Destination=\"(.+?)\".*?>"

        result = re.findall(rx, self._saml)

        if result:
            return result[0]
        raise ValueError("Did not find ACS")

    def get_encryption_algorithm(self):
        """
        Retrieves the encryption algorithm used for certificate. Should be
        "sha1" or "sha256".

        Returns:
            (basestring) Value of encryption algorithm
        Raises:
            (ValueError) Raised when the encryption algorithm
             entry is not found in the data
        """
        rx = r"(?s)<(?:ds:)?SignatureMethod.*?Algorithm=\"(.+?)\".*?>"

        result = re.findall(rx, self._saml)

        if result:
            # TODO: Change to .get('Algorithm') if changing function to soft fail
            algorithm_uri = result[0]
            algorithm = re.findall(r"sha(1|256)", algorithm_uri)
            if not algorithm:
                return ValueError(f"Unexpected algorithm value: {algorithm_uri}")
            return "SHA" + algorithm[0]
        raise ValueError("Did not find algorithm value")

    def get_audience_url(self):
        """
        Retrieves the service provider's Audience URL.

        Returns:
            (basestring) Value of Audience URL algorithm
        Raises:
            (ValueError) Raised when the Audience URL
             entry is not found in the data
        """
        rx = r"(?s)<(?:saml.?:)?Audience(?:\s.*?>|>)(.*?)<\/(?:saml.?:)?Audience>"

        result = re.findall(rx, self._saml)
        if result:
            return result[0]
        raise ValueError("Audience URL not found")

    def get_issuer_uri(self):
        """
        Retrieves the identity provider's Issuer URI.

        Returns:
            (basestring) Value of Issuer URI
        Raises:
            (ValueError) Raised when the Issuer URI
             entry is not found in the data
        """
        rx = r"(?s)<(?:saml.?:)?Issuer.*?>(.*?)<\/(?:saml.?:)?Issuer>"

        result = re.findall(rx, self._saml)

        if result:
            return result[0]
        raise ValueError("Issuer URI not found")

    def get_attributes(self):
        """
        Retrieves the identity provider's claim attributes.

        Returns:
            (dict) Claim attribute values keyed by attribute name
        Raises:
            (ValueError) Raised when the attributes
             are not found in the data
        """
        rx = r"(?s)<(?:saml.?:)?Attribute.*?Name=\"(.+?)\".*?>.*?<(?:saml.?:)?AttributeValue.*?>(.*?)" \
             r"<\/(?:saml.?:)?AttributeValue>.*?<\/(?:saml.?:)?Attribute>"

        result = re.findall(rx, self._saml)

        if not result:
            raise ValueError("Attributes not found")
        return {k: v if v else "" for k, v in result}

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

    def is_saml_request(self):
        """
        Determines if received SAML data is actually a SAML request instead of response

        Returns:
            (bool) True if it is a request, False otherwise
        """
        return "AuthnRequest" in self.get_xml()

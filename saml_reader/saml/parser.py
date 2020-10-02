"""
This module implements features related to parsing the actual SAML response data
and pulling specific pieces of information from the contents of the response document.

In large part, the functionality builds on the python3-saml package produced by OneLogin.
"""

import re

from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.utils import OneLogin_Saml2_Utils as utils

from saml_reader.saml.base import BaseSamlParser


class SamlResponseEncryptedError(Exception):
    """
    Custom exception type raised when SAML responses are encrypted
    """
    pass


class StandardSamlParser(BaseSamlParser):
    """
    Wrapper around OneLogin SAML response parser, adding functionality to
    grab fields other than what is supported by default.
    """

    class _OLISamlParser(OneLogin_Saml2_Response):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def query_assertion(self, path):
            return self._OneLogin_Saml2_Response__query_assertion(path)

        def query(self, path):
            return self._OneLogin_Saml2_Response__query(path)

    def __init__(self, response, url_decode=False):
        """
        Parses SAML response from base64 input.

        Args:
            response (basestring): SAML response as a base64-encoded string
            url_decode (bool): True performs url decoding before parsing. Default: False.

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        # TODO: Add a kwarg to URL-decode the base64 before parsing because if someone
        #       pulled the SAML response from a HAR directly or from the developer console,
        #       they may pull a URL-encoded version
        try:
            self._saml = self._OLISamlParser(
                None,
                response if not url_decode else utils.b64decode(response)
            )
        except AttributeError as e:
            if 'get_sp_key' in e.args[0]:
                raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key")

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

        return cls(base64, url_decode=url_decode)

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
            (basestring) Value of encryption algorithm
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
        Retrieves the identity provider's Audience URL.

        Returns:
            (basestring) Value of encryption algorithm
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
            (basestring) Value of encryption algorithm
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

    def get_xml(self):
        """
        Return raw XML of SAML response

        Returns:
            (basestring) SAML response as XML string
        """
        return self._saml.response

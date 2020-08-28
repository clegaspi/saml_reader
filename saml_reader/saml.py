"""
This module implements features related to parsing the actual SAML response data
and pulling specific pieces of information from the contents of the response document.

In large part, the functionality builds on the python3-saml package produced by OneLogin.
"""

from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.utils import OneLogin_Saml2_Utils as utils


class SamlResponseEncryptedError(Exception):
    """
    Custom exception type raised when SAML responses are encrypted
    """
    pass


class SamlParser(OneLogin_Saml2_Response):
    """
    Wrapper around OneLogin SAML response parser, adding functionality to
    grab fields other than what is supported by default.
    """
    def __init__(self, response):
        """
        Parses SAML response from base64 input.

        Args:
            response (basestring): SAML response as a base64-encoded string

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        try:
            super().__init__(None, response)
        except AttributeError as e:
            if 'get_sp_key' in e.args[0]:
                raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key")

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

    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string
        Raises:
            (ValueError) Raised when the certificate entry is not found in the data
        """
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
        if result:
            return result[0].text
        # Maybe change these functions to return none instead of failing hard
        raise ValueError("Did not find certificate")

    def get_subject_nameid(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            return result[0].text
        raise ValueError("Did not find Name ID")

    def get_subject_nameid_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            # Change to .get('Format') if changing function to soft fail
            return result[0].attrib['Format']
        raise ValueError("Did not find Name ID Format")

    def get_acs(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL
        Raises:
            (ValueError) Raised when the Assertion Consumer Service
             entry is not found in the data
        """
        result = self._OneLogin_Saml2_Response__query(
            '/samlp:Response')
        if result:
            # Change to .get('Destination') if changing function to soft fail
            return result[0].attrib['Destination']
        raise ValueError("Did not find ACS")

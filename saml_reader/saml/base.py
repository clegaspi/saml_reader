from abc import ABC, abstractmethod


class BaseSamlParser(ABC):
    """
    Generalized SAML response parser
    """

    def __init__(self):
        """
        Parses SAML response from base64 input.

        Args:
            response (basestring): SAML response as a base64-encoded string

        Raises:
            (SamlResponseEncryptedError) Raised when SAML response is encrypted
        """
        pass

    @classmethod
    @abstractmethod
    def from_xml(cls, xml):
        """
        Instantiates the class using XML input.

        Args:
            xml (basestring): SAML response as stringified XML document

        Returns:
            (SamlParser) parsed SAML response object
        """
        pass

    @classmethod
    @abstractmethod
    def from_base64(cls, base64):
        """
        Instantiates the class using base64-encoded XML input.

        Args:
            base64 (basestring): SAML response as base64-encoded XML document

        Returns:
            (SamlParser) parsed SAML response object
        """
        pass

    @abstractmethod
    def get_certificate(self):
        """
        Retrieves text of X.509 public certificate included in the SAML response.

        Returns:
            (basestring) Certificate contents as string
        Raises:
            (ValueError) Raised when the certificate entry is not found in the data
        """
        pass

    @abstractmethod
    def get_subject_name_id(self):
        """
        Retrieves the Name ID value from the subject section.

        Returns:
            (basestring) Value of the Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        pass

    @abstractmethod
    def get_subject_name_id_format(self):
        """
        Retrieves the Name ID format from the subject section.

        Returns:
            (basestring) Format attribute of Name ID
        Raises:
            (ValueError) Raised when the Name ID entry is not found in the data
        """
        pass

    @abstractmethod
    def get_assertion_consumer_service_url(self):
        """
        Retrieves the service provider's Assertion Consumer Service URL.

        Returns:
            (basestring) Value of Assertion Consumer Service URL
        Raises:
            (ValueError) Raised when the Assertion Consumer Service
             entry is not found in the data
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def get_audience_url(self):
        """
        Retrieves the service provider's Audience URL.

        Returns:
            (basestring) Value of encryption algorithm
        Raises:
            (ValueError) Raised when the Audience URL
             entry is not found in the data
        """
        pass

    @abstractmethod
    def get_issuer_uri(self):
        """
        Retrieves the identity provider's Audience URL.

        Returns:
            (basestring) Value of encryption algorithm
        Raises:
            (ValueError) Raised when the Issuer URI
             entry is not found in the data
        """
        pass

    @abstractmethod
    def get_attributes(self):
        """
        Retrieves the identity provider's claim attributes.

        Returns:
            (basestring) Value of encryption algorithm
        Raises:
            (ValueError) Raised when the attributes
             are not found in the data
        """
        pass

    @abstractmethod
    def is_assertion_found(self):
        """
        Checks if the response contains exactly one assertion.

        Returns:
            (bool): True if the response contains one assertion, False otherwise
        """
        pass

    @abstractmethod
    def get_xml(self, pretty=False):
        """
        Return raw XML of SAML response

        Args:
            pretty (bool): Pretty-prints XML if True. False is XML in one line.
                Default: False.

        Returns:
            (basestring) SAML response as XML string
        """
        pass

    @abstractmethod
    def is_saml_request(self):
        """
        Determines if received SAML data is actually a SAML request instead of response

        Returns:
            (bool) True if it is a request, False otherwise
        """
        pass

    @abstractmethod
    def found_any_values(self):
        """
        Checks to see if we were able to parse any values at all

        Returns:
            (bool) True if any values were able to be parsed, False otherwise
        """
        pass

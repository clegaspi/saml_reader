"""
This module implements features related to parsing certificate contents retrieved from
SAML responses.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class Certificate(object):
    """
    Wrapper around cryptography's x509 parser for PEM certificates with
    helper functions to retrieve relevant data from the certificate
    """
    def __init__(self, cert_string):
        """
        Creates certificate object from raw certificate content (without header/footer)

        Args:
            cert_string: certificate contents without header/footer
        """
        # TODO: Update this with kwarg to add header/footer to make more extensible
        full_cert = '-----BEGIN CERTIFICATE-----\n' + cert_string + \
                    '\n-----END CERTIFICATE-----'
        decoded_cert = x509.load_pem_x509_certificate(bytes(full_cert, 'utf-8'),
                                                      default_backend())
        self._certificate = decoded_cert

    def get_subject(self, as_string=False):
        """
        Gets the certificate subject contents

        Args:
            as_string (bool): True returns the subject as a string,
                False returns the subject as a dict keyed by field name

        Returns:
            (string, dict) value of subject field
        """
        if as_string:
            return self._certificate.subject.rfc4514_string()
        subject_dict = dict()
        for subject in self._certificate.subject.rdns:
            field, value = subject.rfc4514_string().split("=", 1)
            subject_dict[field] = value
        return subject_dict

    def get_organization_name(self):
        """
        Get organization section of certificate subject

        Returns:
            (basestring) subject organization
        """
        return self.get_subject().get("O")

    def get_common_name(self):
        """
        Get common name section of certificate subject

        Returns:
            (basestring) subject common name
        """
        return self.get_subject().get("CN")

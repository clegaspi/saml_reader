from cryptography import x509
from cryptography.hazmat.backends import default_backend


class Certificate(object):
    def __init__(self, cert_string):
        full_cert = '-----BEGIN CERTIFICATE-----\n' + cert_string + \
                    '\n-----END CERTIFICATE-----'
        decoded_cert = x509.load_pem_x509_certificate(bytes(full_cert, 'utf-8'),
                                                      default_backend())
        self._certificate = decoded_cert

    def get_subject(self, as_string=False):
        if as_string:
            return self._certificate.subject.rfc4514_string()
        subject_dict = dict()
        for subject in self._certificate.subject.rdns:
            field, value = subject.rfc4514_string().split("=", 1)
            subject_dict[field] = value
        return subject_dict

    def get_organization_name(self):
        return self.get_subject().get("O")

    def get_common_name(self):
        return self.get_subject().get("CN")

import unittest

from saml_reader.cert import Certificate


class CertificateTests(unittest.TestCase):
    # The x509 certificate used here is a self-signed certificate from
    # https://www.samltool.com/self_signed_certs.php and carries no validity for any real system.

    def setUp(self):
        self.cert_data = """MIICsjCCAhugAwIBAgIBADANBgkqhkiG9w0BAQ0FADB2MQswCQYDVQQGEwJ1czET
MBEGA1UECAwKQ2FsaWZvcm5pYTEYMBYGA1UECgwPRm9vIEVudGVycHJpc2VzMRAw
DgYDVQQDDAdmb28uY29tMRAwDgYDVQQHDAdBbnl0b3duMRQwEgYDVQQLDAtCYXIg
SGFja2VyczAeFw0yMTAzMjEwNTU1MzRaFw0yMjAzMjEwNTU1MzRaMHYxCzAJBgNV
BAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRgwFgYDVQQKDA9Gb28gRW50ZXJw
cmlzZXMxEDAOBgNVBAMMB2Zvby5jb20xEDAOBgNVBAcMB0FueXRvd24xFDASBgNV
BAsMC0JhciBIYWNrZXJzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCe2Ks8
RJ076uDQEuVsfzgqzjRRveW5IFyq7JS8kui0oDzEAGKEoCRQdtEXsQV+SGC59Aw/
oWkjr4R5ES9uOsey2q6fux27axisM0enZouZUxK1/p7Ac7p/WvqJ0rUZPv7Vaivk
deHD+x9XKF8nwE+qUXcoZxsmkYQVHoJRtLQh0wIDAQABo1AwTjAdBgNVHQ4EFgQU
qdfqajF6ln6wLv93sefMpk044m0wHwYDVR0jBBgwFoAUqdfqajF6ln6wLv93sefM
pk044m0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQCaFCsqsZQn8Pbp
zHE0j5Nv4jkETpiAP5CnBpl+M2icJDFO/9nyLNTm8uX357Sx2UKKjh1pjJE3RYal
RIunxMna1LIuDdwB+my11qbq7jh8HhHtpqr7XQ2256zLgJUyW/El/HjEP31antDu
qIOIVbHWPK7mJ7ObtI/kFXG/gbdaRw=="""

    def test_load_cert_with_linebreaks(self):
        try:
            _ = Certificate(self.cert_data)
        except Exception as e:
            self.fail(f"Test raised exception: {e}")

    def test_load_cert_without_linebreaks(self):
        cert_data_no_linebreaks = self.cert_data.replace('\n', '')
        try:
            _ = Certificate(cert_data_no_linebreaks)
        except Exception as e:
            self.fail(f"Test raised exception: {e}")

    def test_get_subject_as_dict(self):
        cert = Certificate(self.cert_data)
        actual_subject = cert.get_subject()
        expected_subject = {
            'C': 'us',
            'ST': 'California',
            'O': 'Foo Enterprises',
            'CN': 'foo.com',
            'L': 'Anytown',
            'OU': 'Bar Hackers'
        }
        self.assertEqual(actual_subject, expected_subject)

    def test_get_subject_as_str(self):
        cert = Certificate(self.cert_data)
        actual_subject = cert.get_subject(as_string=True)
        expected_subject = "OU=Bar Hackers,L=Anytown,CN=foo.com,O=Foo Enterprises,ST=California,C=us"
        self.assertEqual(actual_subject, expected_subject)

    def test_get_organization(self):
        cert = Certificate(self.cert_data)
        actual_org = cert.get_organization_name()
        expected_org = "Foo Enterprises"
        self.assertEqual(actual_org, expected_org)

    def test_get_common_name(self):
        cert = Certificate(self.cert_data)
        actual_cn = cert.get_common_name()
        expected_cn = "foo.com"
        self.assertEqual(actual_cn, expected_cn)


if __name__ == '__main__':
    unittest.main()

import re

EMAIL_REGEX_MATCH = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
REQUIRED_ATTRIBUTES = {
    'firstName',
    'lastName',
    'email'
}
ATTRIBUTE_VERIFICATION_REGEX = {
    r"\b\S+\b",
    r"\b\S+\b",
    EMAIL_REGEX_MATCH
}
VALID_NAME_ID_FORMATS = {
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
}


class MongoVerifier:
    """

    """

    def __init__(self, saml, cert=None):
        self._saml = saml
        self._cert = cert

    def get_identity_provider(self):
        if self._cert:
            return self._cert.get_organization_name() or self._cert.get_common_name()
        return None

    def get_issuer(self):
        issuers = self._saml.get_issuers()
        if issuers:
            return issuers[0]
        return None

    def verify_issuer(self, expected_value):
        return self.get_issuer() == expected_value

    def get_audience_uri(self):
        audiences = self._saml.get_audiences()
        if audiences:
            return audiences[0]
        return None

    def verify_audience_uri(self, expected_value):
        return self.get_audience_uri() == expected_value

    def get_assertion_consumer_service_url(self):
        return self._saml.get_acs()

    def get_encryption_algorithm(self):
        raise NotImplementedError

    def verify_encryption_algorithm(self, expected_value):
        raise NotImplementedError

    def get_name_id(self):
        return self._saml.get_subject_nameid()

    def verify_name_id(self):
        return self._matches_regex(EMAIL_REGEX_MATCH, self.get_name_id())

    @staticmethod
    def _matches_regex(regex, value):
        matcher = re.compile(regex)
        if matcher.fullmatch(value):
            return True
        return False

    def get_name_id_format(self):
        return self._saml.get_subject_nameid_format()

    def verify_name_id_format(self):
        return self.get_name_id_format() in VALID_NAME_ID_FORMATS

    def get_claim_attributes(self):
        return {k: v[0] for k, v in self._saml.get_attributes().items()}

    def verify_response_has_required_claim_attributes(self):
        attribs = self.get_claim_attributes()
        missing_required_attributes = REQUIRED_ATTRIBUTES - set(attribs.keys())
        return missing_required_attributes

    def verify_claim_attributes_values_are_valid(self):
        attribs = self.get_claim_attributes()
        tests_by_attribute = {name: test for name, test in
                              zip(REQUIRED_ATTRIBUTES, ATTRIBUTE_VERIFICATION_REGEX)}
        bad_attributes = set()
        for name, value in attribs.items():
            if name in tests_by_attribute:
                if not self._matches_regex(tests_by_attribute[name], value):
                    bad_attributes.add(name)

        return bad_attributes

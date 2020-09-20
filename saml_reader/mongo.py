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

    def verify_name_id_and_email_are_the_same(self):
        # Not a requirement, but may indicate that a setting is incorrect
        name_id = self.get_name_id()
        email = self.get_claim_attributes().get("email")

        return name_id and email and name_id == email


class MongoFederationConfig:
    """

    """
    class __ValueNotSet:
        pass

    __NOT_SET = __ValueNotSet()

    def __init__(self, first_name=__NOT_SET, last_name=__NOT_SET, email=__NOT_SET,
                 issuer=__NOT_SET, acs=__NOT_SET, audience=__NOT_SET, encryption=__NOT_SET):

        invalid_attributes = set()

        self.first_name = first_name
        if first_name is not self.__NOT_SET and not self._verify_first_name():
            invalid_attributes.add(("First Name", first_name))

        self.last_name = last_name
        if last_name is not self.__NOT_SET and not self._verify_last_name():
            invalid_attributes.add(("Last Name", last_name))

        self.email = email
        if email is not self.__NOT_SET and not self._verify_email():
            invalid_attributes.add(("E-mail", email))

        self.issuer = issuer
        if issuer is not self.__NOT_SET and not self._verify_issuer():
            invalid_attributes.add(("Issuer URI", issuer))

        self.acs = acs
        if acs is not self.__NOT_SET and not self._verify_acs():
            invalid_attributes.add(("Assertion Consumer Service URL", acs))

        self.audience = audience
        if audience is not self.__NOT_SET and not self._verify_audience():
            invalid_attributes.add(("Audience URI", audience))

        self.encryption = encryption
        if encryption is not self.__NOT_SET and not self._verify_encryption():
            invalid_attributes.add(("Encryption Algorithm", encryption))

    def _verify_first_name(self):
        if re.match(r"\S+", self.first_name):
            return True
        return False

    def _verify_last_name(self):
        if re.match(r"\S+", self.last_name):
            return True
        return False

    def _verify_email(self):
        if re.fullmatch(EMAIL_REGEX_MATCH, self.email):
            return True
        return False

    def _verify_issuer(self):
        if re.match(r"\S+", self.first_name):
            return True
        return False

    def _verify_acs(self):
        if re.fullmatch(r"^https:\/\/auth\.mongodb\.com\/sso\/saml2\/[a-z0-9A-Z]{20}$", self.acs):
            return True
        return False

    def _verify_audience(self):
        if re.fullmatch(r"^https:\/\/www\.okta\.com\/saml2\/service-provider\/[a-z]{20}$", self.audience):
            return True
        return False

    def _verify_encryption(self):
        if self.encryption in {'SHA-256', 'SHA-1'}:
            return True
        return False


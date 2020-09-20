import re

EMAIL_REGEX_MATCH = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"


class MongoVerifier:
    """

    """

    REQUIRED_ATTRIBUTES = {
        'firstName',
        'lastName',
        'email'
    }
    ATTRIBUTE_VALIDATION_REGEX = {
        r"^\s*\S+.*$",
        r"^\s*\S+.*$",
        EMAIL_REGEX_MATCH
    }
    VALID_NAME_ID_FORMATS = {
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    }

    def __init__(self, saml, cert=None, comparison_values=None):
        self._saml = saml
        self._cert = cert
        self._comparison_values = comparison_values
        self._validated = False
        self._errors = []

    def has_certificate(self):
        return self._cert is not None

    def validate_configuration(self):
        if not self.verify_name_id():
            self._errors.append("The Name ID does not appear to be an email address.")

        if not self.verify_name_id_format():
            err_msg = "The Name ID format is not an acceptable format. Acceptable formats:"
            for fmt in self.VALID_NAME_ID_FORMATS:
                err_msg += f"\n - {fmt}"
            self._errors.append(err_msg)

        if not self.verify_name_id_and_email_are_the_same():
            self._errors.append("The Name ID and email attributes are not the same. This is not "
                                "necessarily an error, but may indicate there is a misconfiguration.\n"
                                "The value in Name ID will be the user's login username and the value in the\n"
                                "email attribute will be the address where the user receives email messages.")

        missing_attributes = self.verify_response_has_required_claim_attributes()
        if missing_attributes:
            err_msg = "The following required claim attributes are missing or are misspelled (case matters!):"
            for attrib in missing_attributes:
                err_msg += f"\n - {attrib}"
            err_msg += "\nHere are the current attribute names that were sent:"
            for attrib in self.get_claim_attributes().keys():
                err_msg += f"\n - {attrib}"
            self._errors.append(err_msg)

        invalid_attributes = self.verify_claim_attributes_values_are_valid()
        if invalid_attributes:
            err_msg = "The following required claim attributes were included in the SAML response,\n" \
                      "but do not appear to be in a valid format:"
            for name, value in invalid_attributes:
                err_msg += f"\n - {name} ({value})"
            self._errors.append(err_msg)

        if self._comparison_values:
            if not self.verify_issuer(self._comparison_values.get_value('issuer')):
                err_msg = "The Issuer URI in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_issuer()}\n"
                err_msg += f"specified comparison value: {self._comparison_values.get_value('issuer')}"
                err_msg += "Generally, this means that the Atlas configuration needs to be set to match the SAML value"
                self._errors.append(err_msg)
            if not self.verify_audience_uri(self._comparison_values.get_value('audience')):
                err_msg = "The Audience URI in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_audience_uri()}\n"
                err_msg += f"specified comparison value: {self._comparison_values.get_value('audience')}"
                err_msg += "Generally, this means that the Atlas configuration needs to be set to match the SAML value"
                self._errors.append(err_msg)
            if not self.verify_encryption_algorithm(self._comparison_values.get_value('encryption')):
                err_msg = "The encryption algorithm for the SAML response does not " \
                          "match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_encryption_algorithm().upper()}\n"
                err_msg += f"Specified comparison value: " \
                           f"{self._comparison_values.get_value('encryption').upper().replace('-', '')}"
                err_msg += "Generally, this means that the Atlas configuration needs to be set to match the SAML value"
                self._errors.append(err_msg)
            invalid_attribute_match = self.verify_claim_attributes_against_comparison_values()
            if invalid_attribute_match:
                err_msg = "The following required claim attributes do not match the specified comparison values:"
                for attrib in invalid_attribute_match:
                    err_msg += f"\n - Attribute name: {attrib}"
                    err_msg += f"\n   SAML value: {self.get_claim_attributes()[attrib]}"
                    err_msg += f"\n   Specified comparison value: {self._comparison_values.get_value(attrib)}"
                err_msg += "Generally, this means that the identity provider configuration needs to be reconfigured\n" \
                           "to match the expected values"
                self._errors.append(err_msg)

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
        return self._saml.get_encryption_algorithm()

    def verify_encryption_algorithm(self, expected_value):
        algorithm = self.get_encryption_algorithm()
        if (expected_value.endswith("256") and algorithm.endswith("256")) or \
           (expected_value.endswith("1") and algorithm.endswith("1")):
            return True
        return False

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
        return self.get_name_id_format() in self.VALID_NAME_ID_FORMATS

    def get_claim_attributes(self):
        return {k: v[0] for k, v in self._saml.get_attributes().items()}

    def verify_response_has_required_claim_attributes(self):
        attribs = self.get_claim_attributes()
        missing_required_attributes = self.REQUIRED_ATTRIBUTES - set(attribs.keys())
        return missing_required_attributes

    def verify_claim_attributes_values_are_valid(self):
        attribs = self.get_claim_attributes()
        tests_by_attribute = {name: test for name, test in
                              zip(self.REQUIRED_ATTRIBUTES, self.ATTRIBUTE_VALIDATION_REGEX)}
        bad_attributes = set()
        for name, value in attribs.items():
            if name in tests_by_attribute:
                if not self._matches_regex(tests_by_attribute[name], value):
                    bad_attributes.add((name, value))

        return bad_attributes

    def verify_name_id_and_email_are_the_same(self):
        # Not a requirement, but may indicate that a setting is incorrect
        name_id = self.get_name_id()
        email = self.get_claim_attributes().get("email")

        return name_id and email and name_id == email

    def verify_claim_attributes_against_comparison_values(self):
        claim_attributes = self.get_claim_attributes()
        invalid_attributes = set()
        for attrib in self.REQUIRED_ATTRIBUTES:
            if attrib in claim_attributes:
                comparison_value = self._comparison_values.get_value(attrib)
                if comparison_value and claim_attributes[attrib] != comparison_value:
                    invalid_attributes.add(attrib)
        return invalid_attributes

    def get_error_messages(self):
        return self._errors


class MongoFederationConfig:
    """

    """

    INPUT_VALIDATION_REGEX_BY_ATTRIB = {
        'firstName': r'^\s*\S+.*$',
        'lastName': r'^\s*\S+.*$',
        'email': EMAIL_REGEX_MATCH,
        'issuer': r'^\s*\S+.*$',
        'acs': r'^https:\/\/auth\.mongodb\.com\/sso\/saml2\/[a-z0-9A-Z]{20}$',
        'audience': r'^https:\/\/www\.okta\.com\/saml2\/service-provider\/[a-z]{20}$',
        'encryption': r'^sha-?(1|256)$'
    }

    def __init__(self, **kwargs):
        self._settings = dict()
        if kwargs:
            self.set_values(**kwargs)

    def get_value(self, value_name):
        return self._settings.get(value_name)

    def set_values(self, **kwargs):
        for name, value in kwargs.items():
            self.set_value(name, value)

    def set_value(self, name, value):
        if value is None:
            return

        if name in self.INPUT_VALIDATION_REGEX_BY_ATTRIB:
            if re.fullmatch(self.INPUT_VALIDATION_REGEX_BY_ATTRIB[name], value):
                self._settings[name] = value
            else:
                raise ValueError(f"Attribute '{name}' did not pass input validation")
        else:
            raise ValueError(f"Unknown attribute name: {name}")

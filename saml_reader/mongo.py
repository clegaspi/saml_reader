import re

EMAIL_REGEX_MATCH = r"\b(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b"

VALIDATION_REGEX_BY_ATTRIB = {
    'firstName': r'^\s*\S+.*$',
    'lastName': r'^\s*\S+.*$',
    'email': EMAIL_REGEX_MATCH,
    'issuer': r'^\s*\S+.*$',
    'acs': r'^https:\/\/auth\.mongodb\.com\/sso\/saml2\/[a-z0-9A-Z]{20}$',
    'audience': r'^https:\/\/www\.okta\.com\/saml2\/service-provider\/[a-z]{20}$',
    'encryption': r'^(?i)sha-?(1|256)$'
}


class MongoVerifier:
    """

    """

    VALID_NAME_ID_FORMATS = {
        'urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified',
        'urn:oasis:names:tc:SAML:1.0:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    }

    REQUIRED_CLAIMS = {
        'firstName',
        'lastName',
        'email'
    }

    OPTIONAL_CLAIMS = {
        # There are no currently supported optional claims
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
        is_problem_with_name_id = False
        if not self.verify_name_id_exists():
            is_problem_with_name_id = True
            self._errors.append(f"The Name ID is missing from the SAML Subject.\n"
                                f"Please be sure the customer's identity provider is\n"
                                f"emitting this attribute (it is not emitted by default for Microsoft ADFS)")

        if not is_problem_with_name_id:
            if not self.verify_name_id_pattern():
                is_problem_with_name_id = True
                self._errors.append(f"The Name ID does not appear to be an email address.\n"
                                    f"Name ID: {self.get_name_id()}")

            if not self.verify_name_id_format():
                is_problem_with_name_id = True
                err_msg = "The Name ID format is not an acceptable format.\n"
                err_msg += f"SAML value: {self.get_name_id_format()}\n"
                err_msg += "Acceptable formats:"
                for fmt in self.VALID_NAME_ID_FORMATS:
                    err_msg += f"\n - {fmt}"
                self._errors.append(err_msg)

        missing_attributes = self.verify_response_has_required_claim_attributes()
        if missing_attributes:
            err_msg = "The following required claim attributes are missing or are misspelled (case matters!):"
            for attrib in missing_attributes:
                err_msg += f"\n - {attrib}"
            err_msg += "\nHere are the current attribute names that were sent:"
            for attrib in self.get_claim_attributes().keys():
                err_msg += f"\n - {attrib}"
            self._errors.append(err_msg)

        invalid_attributes = self.verify_claim_attributes_values_pattern()
        if invalid_attributes:
            err_msg = "The following required claim attributes were included in the SAML response,\n" \
                      "but do not appear to be in a valid format:"
            for name, value in invalid_attributes:
                err_msg += f"\n - {name} ({value})"
            self._errors.append(err_msg)

        if not is_problem_with_name_id and \
                'email' not in missing_attributes and \
                'email' not in invalid_attributes:
            if not self.verify_name_id_and_email_are_the_same():
                self._errors.append("The Name ID and email attributes are not the same. This is not\n"
                                    "necessarily an error, but may indicate there is a misconfiguration.\n"
                                    "The value in Name ID will be the user's login username and the value in the\n"
                                    "email attribute will be the address where the user receives email messages.")

        if not self.verify_issuer_pattern():
            self._errors.append(f"The Issuer URI does not match the anticipated pattern.\n"
                                f"Issuer URI: {self.get_issuer()}")

        if not self.verify_audience_uri_pattern():
            self._errors.append(f"The Audience URI does not match the anticipated pattern.\n"
                                f"Audience URI: {self.get_audience_uri()}")

        if not self.verify_assertion_consumer_service_url_pattern():
            self._errors.append(f"The Assertion Consumer Service URL does not match the anticipated pattern.\n"
                                f"ACS URL: {self.get_assertion_consumer_service_url()}")

        if not self.verify_encryption_algorithm_pattern():
            self._errors.append(f"The encryption algorithm does not match the anticipated pattern.\n"
                                f"Encryption Algorithm: {self.get_encryption_algorithm()}")

        if self._comparison_values:
            value = self._comparison_values.get_value('email')
            if value and not is_problem_with_name_id and not self.verify_name_id(value):
                err_msg = "The Name ID does not match the provided e-mail value:\n"
                err_msg += f"Name ID value: {self.get_name_id()}\n"
                err_msg += f"Specified email value: {self._comparison_values.get_value('email')}"
                err_msg += "\nThis is not necessarily an error, but may indicate there is a misconfiguration.\n" \
                           "The value in Name ID will be the user's login username and the value in the\n" \
                           "email attribute will be the address where the user receives email messages."
                self._errors.append(err_msg)
            value = self._comparison_values.get_value('issuer')
            if value and not self.verify_issuer(value):
                err_msg = "The Issuer URI in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_issuer()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('issuer')}"
                err_msg += "\nGenerally, this means that the Atlas configuration needs " \
                           "to be set to match the SAML value"
                self._errors.append(err_msg)
            value = self._comparison_values.get_value('audience')
            if value and not self.verify_audience_uri(value):
                err_msg = "The Audience URI in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_audience_uri()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('audience')}"
                err_msg += "\nGenerally, this means that the Atlas configuration needs " \
                           "to be set to match the SAML value"
                self._errors.append(err_msg)
            value = self._comparison_values.get_value('acs')
            if value and not self.verify_assertion_consumer_service_url(value):
                err_msg = "The Assertion Consumer Service URL in the SAML response does not match the " \
                          "specified comparison value:\n"
                err_msg += f"SAML value: {self.get_assertion_consumer_service_url()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('acs')}"
                err_msg += "\nThis means that the identity provider configuration needs\n" \
                           "to be reconfigured to match the expected value"
                self._errors.append(err_msg)
            value = self._comparison_values.get_value('encryption')
            if value and not self.verify_encryption_algorithm(value):
                err_msg = "The encryption algorithm for the SAML response does not " \
                          "match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_encryption_algorithm()}\n"
                err_msg += f"Specified comparison value: " \
                           f"{self._comparison_values.get_value('encryption')}"
                err_msg += "\nGenerally, this means that the Atlas configuration needs " \
                           "to be set to match the SAML value"
                self._errors.append(err_msg)
            invalid_attribute_match = self.verify_claim_attributes_against_comparison_values()
            if invalid_attribute_match:
                err_msg = "The following required claim attributes do not match the specified comparison values:"
                for attrib in invalid_attribute_match:
                    err_msg += f"\n - Attribute name: {attrib}"
                    err_msg += f"\n   SAML value: {self.get_claim_attributes()[attrib]}"
                    err_msg += f"\n   Specified comparison value: {self._comparison_values.get_value(attrib)}"
                err_msg += "\nGenerally, this means that the identity provider configuration needs\n" \
                           "to be reconfigured to match the expected values"
                self._errors.append(err_msg)
        self._validated = True

    def validated(self):
        return self._validated

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

    def verify_issuer_pattern(self):
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['issuer'],
                                   self.get_issuer())

    def get_audience_uri(self):
        audiences = self._saml.get_audiences()
        if audiences:
            return audiences[0]
        return None

    def verify_audience_uri(self, expected_value):
        return self.get_audience_uri() == expected_value

    def verify_audience_uri_pattern(self):
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['audience'],
                                   self.get_audience_uri())

    def get_assertion_consumer_service_url(self):
        return self._saml.get_acs()

    def verify_assertion_consumer_service_url(self, expected_value):
        return self.get_assertion_consumer_service_url() == expected_value

    def verify_assertion_consumer_service_url_pattern(self):
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['acs'],
                                   self.get_assertion_consumer_service_url())

    def get_encryption_algorithm(self):
        return self._saml.get_encryption_algorithm()

    def verify_encryption_algorithm(self, expected_value):
        return self.get_encryption_algorithm() == expected_value

    def verify_encryption_algorithm_pattern(self):
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['encryption'],
                                   self.get_encryption_algorithm())

    def get_name_id(self):
        try:
            name_id = self._saml.get_subject_nameid()
        except ValueError:
            return None
        return name_id

    def verify_name_id(self, expected_value):
        return self.get_name_id() == expected_value

    def verify_name_id_exists(self):
        return self.get_name_id() is not None

    def verify_name_id_pattern(self):
        return self._matches_regex(EMAIL_REGEX_MATCH, self.get_name_id())

    @staticmethod
    def _matches_regex(regex, value):
        matcher = re.compile(regex)
        if matcher.fullmatch(value):
            return True
        return False

    def get_name_id_format(self):
        try:
            name_id_format = self._saml.get_subject_nameid_format()
        except ValueError:
            return None
        return name_id_format

    def verify_name_id_format(self):
        return self.get_name_id_format() in self.VALID_NAME_ID_FORMATS

    def get_claim_attributes(self):
        return {k: v[0] for k, v in self._saml.get_attributes().items()}

    def verify_response_has_required_claim_attributes(self):
        attribs = self.get_claim_attributes()
        missing_required_attributes = self.REQUIRED_CLAIMS - set(attribs.keys())
        return missing_required_attributes

    def verify_claim_attributes_values_pattern(self):
        attribs = self.get_claim_attributes()
        bad_attributes = set()
        for name, value in attribs.items():
            if name in self.REQUIRED_CLAIMS:
                if not self._matches_regex(VALIDATION_REGEX_BY_ATTRIB[name], value):
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
        for attrib in set.union(self.REQUIRED_CLAIMS, self.OPTIONAL_CLAIMS):
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

        if name in VALIDATION_REGEX_BY_ATTRIB:
            if re.fullmatch(VALIDATION_REGEX_BY_ATTRIB[name], value):
                self._settings[name] = value
            else:
                raise ValueError(f"Attribute '{name}' did not pass input validation")
        else:
            raise ValueError(f"Unknown attribute name: {name}")

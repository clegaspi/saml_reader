"""
These classes handle all data validation specific to MongoDB Cloud
"""
import re

"""Regular expression to match (most) valid e-mail addresses"""
EMAIL_REGEX_MATCH = r"\b(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b"

"""Regular expressions to validate SAML fields and claim attributes"""
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
    Interprets SAML and certificate data and compares it against expected patterns specific
    to MongoDB Cloud and entered values

    Attributes:
        VALID_NAME_ID_FORMATS (`set` of `basestring`): acceptable formats for Name ID for MongoDB Cloud
        REQUIRED_CLAIMS (`set` of `basestring`): claim attribute names that are required in SAML response
        OPTIONAL_CLAIMS (`set` of `basestring`): claim attributes names that are read and interpreted by
            MongoDB cloud, but are not required
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
        """
        Reads in SAML, certificate data, and any comparison values for important
        parameters.

        Args:
            saml (SamlParser): SAML response
            cert (Certificate, optional): Certificate information
            comparison_values (MongoFederationConfig, optional): user-entered values to check
                against SAML data
        """
        self._saml = saml
        self._cert = cert
        self._comparison_values = comparison_values
        self._validated = False
        self._errors = []

    def has_certificate(self):
        """
        Determine if certificate information is available

        Returns:
            (bool) True if there is certificate data, False otherwise
        """
        return self._cert is not None

    def validate_configuration(self):
        """
        Interprets the SAML and certificate data and identifies anti-patterns and errors
        in the SAML data based on expected patterning of data and entered comparison values.
        Error messages and fixes/explanations are recorded and retrievable by `MongoVerifier.get_errors()`.

        Returns:
            None
        """

        # Check if Name ID exists
        is_problem_with_name_id = False
        if not self.verify_name_id_exists():
            is_problem_with_name_id = True
            self._errors.append(f"The Name ID is missing from the SAML Subject.\n"
                                f"Please be sure the customer's identity provider is\n"
                                f"emitting this attribute (it is not emitted by default for Microsoft ADFS)")

        # If Name ID exists, run other tests that depend on the value being present
        if not is_problem_with_name_id:
            # Verify Name ID against regex
            if not self.verify_name_id_pattern():
                is_problem_with_name_id = True
                self._errors.append(f"The Name ID does not appear to be an email address.\n"
                                    f"Name ID: {self.get_name_id()}")

            # Verify Name ID format is valid
            if not self.verify_name_id_format():
                is_problem_with_name_id = True
                err_msg = "The Name ID format is not an acceptable format.\n"
                err_msg += f"SAML value: {self.get_name_id_format()}\n"
                err_msg += "Acceptable formats:"
                for fmt in self.VALID_NAME_ID_FORMATS:
                    err_msg += f"\n - {fmt}"
                self._errors.append(err_msg)

        # Check to see if any required/optional attributes are missing
        missing_attributes = self.verify_response_has_required_claim_attributes()
        if missing_attributes:
            err_msg = "The following required claim attributes are missing or are misspelled (case matters!):"
            for attrib in missing_attributes:
                err_msg += f"\n - {attrib}"
            err_msg += "\nHere are the current attribute names that were sent:"
            for attrib in self.get_claim_attributes().keys():
                err_msg += f"\n - {attrib}"
            self._errors.append(err_msg)

        # Verify required/optional attributes match expected regex pattern
        invalid_attributes = self.verify_claim_attributes_values_pattern()
        if invalid_attributes:
            err_msg = "The following required claim attributes were included in the SAML response,\n" \
                      "but do not appear to be in a valid format:"
            for name, value in invalid_attributes:
                err_msg += f"\n - {name} ({value})"
            self._errors.append(err_msg)

        # Check if Name ID and email attribute match, if both exist and aren't problematic
        # based on previous validation tests
        if not is_problem_with_name_id and \
                'email' not in missing_attributes and \
                'email' not in invalid_attributes:
            if not self.verify_name_id_and_email_are_the_same():
                self._errors.append("The Name ID and email attributes are not the same. This is not\n"
                                    "necessarily an error, but may indicate there is a misconfiguration.\n"
                                    "The value in Name ID will be the user's login username and the value in the\n"
                                    "email attribute will be the address where the user receives email messages.")

        # Verify Issuer URI matches regex
        if not self.verify_issuer_pattern():
            self._errors.append(f"The Issuer URI does not match the anticipated pattern.\n"
                                f"Issuer URI: {self.get_issuer()}")

        # Verify Audience URL matches regex
        if not self.verify_audience_url_pattern():
            self._errors.append(f"The Audience URL does not match the anticipated pattern.\n"
                                f"Audience URL: {self.get_audience_url()}")

        # Verify ACS URL matches regex
        if not self.verify_assertion_consumer_service_url_pattern():
            self._errors.append(f"The Assertion Consumer Service URL does not match the anticipated pattern.\n"
                                f"ACS URL: {self.get_assertion_consumer_service_url()}")

        # Verify encryption algorithm matches regex (it should but you never know)
        if not self.verify_encryption_algorithm_pattern():
            self._errors.append(f"The encryption algorithm does not match the anticipated pattern.\n"
                                f"Encryption Algorithm: {self.get_encryption_algorithm()}")

        # If user provided comparison values, run comparison tests
        if self._comparison_values:
            # Check that Name ID matches provided e-mail if Name ID is valid
            value = self._comparison_values.get_value('email')
            if value and not is_problem_with_name_id and not self.verify_name_id(value):
                err_msg = "The Name ID does not match the provided e-mail value:\n"
                err_msg += f"Name ID value: {self.get_name_id()}\n"
                err_msg += f"Specified email value: {self._comparison_values.get_value('email')}"
                err_msg += "\nThis is not necessarily an error, but may indicate there is a misconfiguration.\n" \
                           "The value in Name ID will be the user's login username and the value in the\n" \
                           "email attribute will be the address where the user receives email messages."
                self._errors.append(err_msg)

            # Check Issuer URI matches provided value
            value = self._comparison_values.get_value('issuer')
            if value and not self.verify_issuer(value):
                err_msg = "The Issuer URI in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_issuer()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('issuer')}"
                err_msg += "\nGenerally, this means that the Atlas configuration needs " \
                           "to be set to match the SAML value"
                self._errors.append(err_msg)

            # Check Audience URL matches provided value
            value = self._comparison_values.get_value('audience')
            if value and not self.verify_audience_url(value):
                err_msg = "The Audience URL in the SAML response does not match the specified comparison value:\n"
                err_msg += f"SAML value: {self.get_audience_url()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('audience')}"
                err_msg += "\nGenerally, this means that the Atlas configuration needs " \
                           "to be set to match the SAML value"
                self._errors.append(err_msg)

            # Check ACS URL matches provided value
            value = self._comparison_values.get_value('acs')
            if value and not self.verify_assertion_consumer_service_url(value):
                err_msg = "The Assertion Consumer Service URL in the SAML response does not match the " \
                          "specified comparison value:\n"
                err_msg += f"SAML value: {self.get_assertion_consumer_service_url()}\n"
                err_msg += f"Specified comparison value: {self._comparison_values.get_value('acs')}"
                err_msg += "\nThis means that the identity provider configuration needs\n" \
                           "to be reconfigured to match the expected value"
                self._errors.append(err_msg)

            # Check encryption matches provided value
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

            # Check that attributes in SAML matches provided value. If the SAML response
            # doesn't have the attribute, the test is skipped.
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
        """
        Has validation been run yet.

        Returns:
            (bool) True if validation has been run, False otherwise
        """
        return self._validated

    def get_identity_provider(self):
        """
        Get identity provider from certificate. May not show exact identity provider.

        Returns:
            (`basestring` or `None`) Identity provider, if certificate provided, otherwise None
        """

        # TODO: It would be cool to have some expected patterns based on common IdPs so we
        #       could identify the IdP from SAML data and/or see if data matches
        #       what we would expect knowing what the IdP is from the certificate
        if self._cert:
            return self._cert.get_organization_name() or self._cert.get_common_name()
        return None

    def get_issuer(self):
        """
        Get Issuer URI

        Returns:
            (`basestring` or `None`) Issuer URI, if found in the SAML response, otherwise None
        """
        issuers = self._saml.get_issuers()
        if issuers:
            return issuers[0]
        return None

    def verify_issuer(self, expected_value):
        """
        Checks Issuer URI against expected value

        Args:
            expected_value (basestring): expected Issuer URI

        Returns:
            (bool) True if they match, False otherwise
        """
        return self.get_issuer() == expected_value

    def verify_issuer_pattern(self):
        """
        Checks if Issuer URI matches the expected regular expression

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['issuer'],
                                   self.get_issuer())

    def get_audience_url(self):
        """
        Get Audience URL

        Returns:
            (`basestring` or `None`) Audience URL, if found in the SAML response, otherwise None
        """
        audiences = self._saml.get_audiences()
        if audiences:
            return audiences[0]
        return None

    def verify_audience_url(self, expected_value):
        """
        Checks Audience URL against expected value

        Args:
            expected_value (basestring): expected Audience URL

        Returns:
            (bool) True if they match, False otherwise
        """
        return self.get_audience_url() == expected_value

    def verify_audience_url_pattern(self):
        """
        Checks if Audience URL matches the expected regular expression

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['audience'],
                                   self.get_audience_url())

    def get_assertion_consumer_service_url(self):
        """
        Get Assertion Consumer Service (ACS) URL

        Returns:
            (`basestring` or `None`) ACS URI, if found in the SAML response, otherwise None
        """
        return self._saml.get_acs()

    def verify_assertion_consumer_service_url(self, expected_value):
        """
        Checks Assertion Consumer Service URL against expected value

        Args:
            expected_value (basestring): expected ACS URL

        Returns:
            (bool) True if they match, False otherwise
        """
        return self.get_assertion_consumer_service_url() == expected_value

    def verify_assertion_consumer_service_url_pattern(self):
        """
        Checks if Assertion Consumer Service URL matches the expected regular expression

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['acs'],
                                   self.get_assertion_consumer_service_url())

    def get_encryption_algorithm(self):
        """
        Get encryption algorithm

        Returns:
            (`basestring`) Encryption algorithm
        """
        return self._saml.get_encryption_algorithm()

    def verify_encryption_algorithm(self, expected_value):
        """
        Checks encryption algorithm against expected value

        Args:
            expected_value (basestring): expected encryption algorithm
                format expected to be "SHA1" or "SHA256"

        Returns:
            (bool) True if they match, False otherwise
        """
        return self.get_encryption_algorithm() == expected_value

    def verify_encryption_algorithm_pattern(self):
        """
        Checks if encryption algorithm matches the expected regular expression

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return self._matches_regex(VALIDATION_REGEX_BY_ATTRIB['encryption'],
                                   self.get_encryption_algorithm())

    def get_name_id(self):
        """
        Get Name ID

        Returns:
            (`basestring` or `None`) Name ID, if found in the SAML response, otherwise None
        """
        try:
            name_id = self._saml.get_subject_nameid()
        except ValueError:
            return None
        return name_id

    def verify_name_id(self, expected_value):
        """
        Checks Name ID against expected value

        Args:
            expected_value (basestring): expected Name ID

        Returns:
            (bool) True if they match, False otherwise
        """
        return self.get_name_id() == expected_value

    def verify_name_id_exists(self):
        """
        Checks if Name ID exists in the SAML response

        Returns:
            (bool) True if present, False otherwise
        """
        return self.get_name_id() is not None

    def verify_name_id_pattern(self):
        """
        Checks if Name ID matches the expected regular expression

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return self._matches_regex(EMAIL_REGEX_MATCH, self.get_name_id())

    @staticmethod
    def _matches_regex(regex, value):
        """
        Checks if a string matches a given regular expression

        Args:
            regex (basestring): regex string
            value (basestring): string to check against regex

        Returns:
            (bool) True if `value` matches pattern `regex`, False otherwise
        """
        matcher = re.compile(regex)
        if matcher.fullmatch(value):
            return True
        return False

    def get_name_id_format(self):
        """
        Get Name ID format

        Returns:
            (`basestring` or `None`) Name ID format, if found in the SAML response, otherwise None
        """
        try:
            name_id_format = self._saml.get_subject_nameid_format()
        except ValueError:
            return None
        return name_id_format

    def verify_name_id_format(self):
        """
        Checks if Name ID format is one of the valid valuesI

        Returns:
            (bool) True if a valid value, False otherwise
        """
        return self.get_name_id_format() in self.VALID_NAME_ID_FORMATS

    def get_claim_attributes(self):
        """
        Get claim attribute names and values

        Returns:
            (dict) Claim attribute values, keyed by claim name
        """
        return {k: v[0] if v else "" for k, v in self._saml.get_attributes().items()}

    def verify_response_has_required_claim_attributes(self):
        """
        Check if SAML response has all required claims for MongoDB

        Returns:
            (`set` of `basestring`) names of missing required attributes
        """
        attribs = self.get_claim_attributes()
        missing_required_attributes = self.REQUIRED_CLAIMS - set(attribs.keys())
        return missing_required_attributes

    def verify_claim_attributes_values_pattern(self):
        """
        Check that required and optional claim attributes match expected regular expression

        Returns:
            (`set` of `tuple`) names and values as tuples of required and/or optional
                attributes that do not match regex
        """
        attribs = self.get_claim_attributes()
        all_acceptable_attributes = set.union(self.REQUIRED_CLAIMS, self.OPTIONAL_CLAIMS)
        bad_attributes = set()
        for name, value in attribs.items():
            if name in all_acceptable_attributes:
                if not self._matches_regex(VALIDATION_REGEX_BY_ATTRIB[name], value):
                    bad_attributes.add((name, value))

        return bad_attributes

    def verify_name_id_and_email_are_the_same(self):
        """
        Check if Name ID and email values from SAML response match. This is not
        a hard requirement, but is typical and a mismatch may indicate an incorrect
        configuration.

        Returns:
            (bool) True if both values are present in the SAML response and match
        """
        # Not a requirement, but may indicate that a setting is incorrect
        name_id = self.get_name_id()
        email = self.get_claim_attributes().get("email")

        return name_id and email and name_id == email

    def verify_claim_attributes_against_comparison_values(self):
        """
        Check required and optional claim attributes against provided values. Check is only
        performed if a comparison value is provided.

        Returns:
            (`set` of `basestring`) names of attributes which do not match provided values
        """
        claim_attributes = self.get_claim_attributes()
        invalid_attributes = set()
        all_acceptable_attributes = set.union(self.REQUIRED_CLAIMS, self.OPTIONAL_CLAIMS)
        for attrib in all_acceptable_attributes:
            if attrib in claim_attributes:
                comparison_value = self._comparison_values.get_value(attrib)
                if comparison_value and claim_attributes[attrib] != comparison_value:
                    invalid_attributes.add(attrib)
        return invalid_attributes

    def get_error_messages(self):
        """
        Get errors generated during validation

        Returns:
            (`list` of `str`) Error messages generated
        """
        return self._errors


class MongoFederationConfig:
    """
    Stores user-provided federation configuration values for comparison with SAML data
    """

    def __init__(self, **kwargs):
        """
        Set comparison values and verify they match a regular expression (input validation)

        Args:
            **kwargs: currently accepted keywords are:
                - `issuer`: Issuer URI
                - `audience`: Audience URL
                - `acs`: Assertion Consumer Service URL
                - `encryption`: Encryption algorithm
                - `firstName`: expected value for "firstName" claim attribute
                - `lastName`: expected value for "lastName" claim attribute
                - `email`: expected value for Name ID and "email" claim attribute
        """
        self._settings = dict()
        if kwargs:
            self.set_values(kwargs)

    def get_value(self, value_name):
        """
        Get comparison value by name

        Args:
            value_name (basestring): name of comparison value keyword

        Returns:
            (`basestring` or `None`) comparison value, `None` if name does not exist
        """
        return self._settings.get(value_name)

    def set_values(self, value_dict):
        """
        Set multiple comparison values

        Args:
            value_dict (dict): comparison values, keyed by keyword name

        Returns:
            None
        """
        for name, value in value_dict.items():
            self.set_value(name, value)

    def set_value(self, name, value):
        """
        Sets a single comparison value by name and value if it matches input validation.
        See `MongoFederationConfig.__init__()` for the list of valid keywords.

        Args:
            name (basestring): a valid keyword
            value (basestring): comparison value for keyword

        Returns:
            None

        Raises:
            (ValueError) if value doesn't pass validation or keyword is not recognized
        """
        if value is None:
            return

        if name in VALIDATION_REGEX_BY_ATTRIB:
            if re.fullmatch(VALIDATION_REGEX_BY_ATTRIB[name], value):
                self._settings[name] = value
            else:
                raise ValueError(f"Attribute '{name}' did not pass input validation")
        else:
            raise ValueError(f"Unknown attribute name: {name}")

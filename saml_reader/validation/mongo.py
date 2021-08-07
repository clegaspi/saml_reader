"""
These classes handle all data validation specific to MongoDB Cloud
"""
import re
from saml_reader.validation.graph_suite import TestDefinition, TestSuite, TEST_FAIL
from saml_reader.validation.input_validation import MongoFederationConfig, UserInputValidator


class MongoSamlValidator:
    """
    Interprets SAML and certificate data and compares it against expected patterns specific
    to MongoDB Cloud and entered values
    """

    def __init__(self, saml, cert=None, comparison_values=None):
        """
        Reads in SAML, certificate data, and any comparison values for important
        parameters.

        Args:
            saml (BaseSamlParser): SAML response
            cert (Certificate, optional): Certificate information
            comparison_values (MongoFederationConfig, optional): user-entered values to check
                against SAML data
        """
        self._saml = saml
        self._cert = cert
        self._comparison_values = comparison_values or MongoFederationConfig()
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
        Run validation tests on the loaded SAML data and comparison values.

        Returns:
            None
        """
        self._errors = []
        test_suite = MongoTestSuite(self._saml, self._comparison_values)
        test_suite.run()
        self._build_report(test_suite)
        self._validated = True

    def _build_report(self, test_suite):
        """
        Compiles error messages based on validation test results.

        Args:
            test_suite (MongoTestSuite): test suite run on SAML data

        Returns:
            None
        """

        # We want to build the report in the order of how the tests are
        # shown in the list of tests in MongoTestSuite so that results are
        # printed together for related tests.

        test_results = test_suite.get_results()

        # Get list of failed tests in order
        failed_tests = [
            test for test in test_suite.get_list_of_mongo_tests()
            if test_results.get(test) == TEST_FAIL
        ]

        # Get the report messages for the failed tests
        messages = ValidationReport(
            self._saml, self._comparison_values
        ).get_messages_by_name(
            failed_tests
        )

        # Write report messages in order, filtering out any tests with no messages
        self._errors = [
            messages[test] for test in failed_tests if messages[test]
        ]

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
        return self._saml.get_issuer_uri()

    def get_audience_url(self):
        """
        Get Audience URL

        Returns:
            (`basestring` or `None`) Audience URL, if found in the SAML response, otherwise None
        """
        return self._saml.get_audience_url()

    def get_assertion_consumer_service_url(self):
        """
        Get Assertion Consumer Service (ACS) URL

        Returns:
            (`basestring` or `None`) ACS URL, if found in the SAML response, otherwise None
        """
        return self._saml.get_assertion_consumer_service_url()

    def get_encryption_algorithm(self):
        """
        Get encryption algorithm

        Returns:
            (`basestring`) Encryption algorithm
        """
        return self._saml.get_encryption_algorithm()

    def get_name_id(self):
        """
        Get Name ID

        Returns:
            (`basestring` or `None`) Name ID, if found in the SAML response, otherwise None
        """
        return self._saml.get_subject_name_id()

    def get_name_id_format(self):
        """
        Get Name ID format

        Returns:
            (`basestring` or `None`) Name ID format, if found in the SAML response, otherwise None
        """
        return self._saml.get_subject_name_id_format()

    def get_claim_attributes(self):
        """
        Get claim attribute names and values

        Returns:
            (dict) Claim attribute values, keyed by claim name.
                Empty dict if no attributes found.
        """
        return self._saml.get_attributes() or dict()

    def get_missing_claim_attributes(self):
        """
        Get required claims for MongoDB that are missing, if any

        Returns:
            (`set` of `basestring`) names of missing required attributes
        """
        attribs = self.get_claim_attributes()
        missing_required_attributes = MongoTestSuite.REQUIRED_CLAIMS - set(attribs.keys())
        return missing_required_attributes

    def get_error_messages(self):
        """
        Get errors generated during validation

        Returns:
            (`list` of `str`) Error messages generated
        """
        return self._errors


class MongoTestSuite(TestSuite):
    """
    Test suite for SAML responses for comparison against known patterns and comparison values.

    Attributes:
        VALID_NAME_ID_FORMATS (`set` of `basestring`): acceptable formats for Name ID for MongoDB Cloud
        REQUIRED_CLAIMS (`set` of `basestring`): claim attribute names that are required in SAML response
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

    def __init__(self, saml, comparison_values=None):
        """
        Create test suite with supplied SAML and comparison data.

        Args:
            saml (BaseSamlParser): parsed SAML data
            comparison_values (MongoFederationConfig, optional): comparison values to
                compare with data in SAML response. Default: None (no comparison
                tests will be performed)
        """
        super().__init__()
        self.set_context({
            'saml': saml,
            'comparison_values': comparison_values or MongoFederationConfig()
        })
        self._tests = self._get_tests()

    @staticmethod
    def _get_tests():
        """
        Builds test objects for testing SAML data for patterns specific to MongoDB Cloud
        and against supplied comparison values.

        Any future tests should be added to this function in an order which makes logical sense
        with the tests around it.

        Returns:
            (`list` of `TestDefinition`) test objects
        """
        tests = [
            # Name ID and Name ID format tests
            TestDefinition("exists_name_id", MongoTestSuite.verify_name_id_exists,
                           required_context=['saml']),
            TestDefinition("regex_name_id", MongoTestSuite.verify_name_id_pattern,
                           dependencies=['exists_name_id'],
                           required_context=['saml']),
            TestDefinition("exists_name_id_format", MongoTestSuite.verify_name_id_format_exists,
                           dependencies=['exists_name_id'],
                           required_context=['saml']),
            TestDefinition("regex_name_id_format", MongoTestSuite.verify_name_id_format,
                           dependencies=['exists_name_id_format'],
                           required_context=['saml']),

            # Claim attribute tests
            TestDefinition("exists_all_required_attributes", MongoTestSuite.verify_all_required_attributes_exist,
                           required_context=['saml']),
            TestDefinition("exists_first_name", MongoTestSuite.verify_first_name_exists,
                           required_context=['saml']),
            TestDefinition("regex_first_name", MongoTestSuite.verify_first_name_pattern,
                           dependencies=['exists_first_name'],
                           required_context=['saml']),
            TestDefinition("exists_last_name", MongoTestSuite.verify_last_name_exists,
                           required_context=['saml']),
            TestDefinition("regex_last_name", MongoTestSuite.verify_last_name_pattern,
                           dependencies=['exists_last_name'],
                           required_context=['saml']),
            TestDefinition("exists_email", MongoTestSuite.verify_email_exists,
                           required_context=['saml']),
            TestDefinition("regex_email", MongoTestSuite.verify_email_pattern,
                           dependencies=['exists_email'],
                           required_context=['saml']),
            TestDefinition("exists_member_of", MongoTestSuite.verify_member_of_exists,
                           required_context=['saml']),
            TestDefinition("member_of_not_empty", MongoTestSuite.verify_member_of_not_empty,
                           dependencies=['exists_member_of'],
                           required_context=['saml']),
            TestDefinition("regex_member_of", MongoTestSuite.verify_member_of_pattern,
                           dependencies=['member_of_not_empty'],
                           required_context=['saml']),

            # Claim attribute comparison tests
            TestDefinition("exists_comparison_first_name", MongoTestSuite.verify_first_name_comparison_exists,
                           dependencies=['regex_first_name'],
                           required_context=['comparison_values']),
            TestDefinition("compare_first_name", MongoTestSuite.verify_first_name,
                           dependencies=['exists_comparison_first_name'],
                           required_context=['saml', 'comparison_values']),
            TestDefinition("exists_comparison_last_name", MongoTestSuite.verify_last_name_comparison_exists,
                           dependencies=['regex_last_name'],
                           required_context=['comparison_values']),
            TestDefinition("compare_last_name", MongoTestSuite.verify_last_name,
                           dependencies=['exists_comparison_last_name'],
                           required_context=['saml', 'comparison_values']),
            TestDefinition("exists_comparison_email", MongoTestSuite.verify_email_comparison_exists,
                           dependencies=['regex_email'],
                           required_context=['comparison_values']),
            TestDefinition("compare_email", MongoTestSuite.verify_email,
                           dependencies=['exists_comparison_email'],
                           required_context=['saml', 'comparison_values']),
            TestDefinition("member_of_is_expected", MongoTestSuite.verify_member_of_is_expected,
                           dependencies=[('exists_member_of', TEST_FAIL)],
                           required_context=['comparison_values']),
            TestDefinition("exists_comparison_member_of", MongoTestSuite.verify_member_of_comparison_exists,
                           dependencies=['regex_member_of'],
                           required_context=['comparison_values']),
            TestDefinition("compare_member_of", MongoTestSuite.verify_member_of,
                           dependencies=['exists_comparison_member_of'],
                           required_context=['saml', 'comparison_values']),

            # Federated domain tests
            TestDefinition("exists_comparison_domain", MongoTestSuite.verify_domain_comparison_exists,
                           required_context=['comparison_values']),
            TestDefinition("compare_domain_email", MongoTestSuite.verify_domain_in_email,
                           dependencies=['regex_email', 'exists_comparison_domain'],
                           required_context=['saml', 'comparison_values']),
            TestDefinition("compare_domain_comparison_email", MongoTestSuite.verify_domain_in_comparison_email,
                           dependencies=['exists_comparison_email', 'exists_comparison_domain'],
                           required_context=['comparison_values']),
            TestDefinition("compare_domain_name_id", MongoTestSuite.verify_domain_in_name_id,
                           dependencies=['regex_name_id', 'exists_comparison_domain'],
                           required_context=['saml', 'comparison_values']),

            # Email and Name ID comparison tests
            TestDefinition("compare_email_name_id", MongoTestSuite.verify_name_id,
                           dependencies=['regex_name_id', 'exists_comparison_email'],
                           required_context=['saml', 'comparison_values']),
            TestDefinition("match_name_id_email_in_saml", MongoTestSuite.verify_name_id_and_email_are_the_same,
                           dependencies=['regex_email', 'regex_name_id'],
                           required_context=['saml']),

            # Issuer URI tests
            TestDefinition("exists_issuer", MongoTestSuite.verify_issuer_exists,
                           required_context=['saml']),
            TestDefinition("regex_issuer", MongoTestSuite.verify_issuer_pattern,
                           dependencies=['exists_issuer'],
                           required_context=['saml']),
            TestDefinition("exists_comparison_issuer", MongoTestSuite.verify_issuer_comparison_exists,
                           dependencies=['regex_issuer'],
                           required_context=['comparison_values']),
            TestDefinition("match_issuer", MongoTestSuite.verify_issuer,
                           dependencies=['exists_comparison_issuer'],
                           required_context=['saml', 'comparison_values']),

            # Audience URL tests
            TestDefinition("exists_audience", MongoTestSuite.verify_audience_url_exists,
                           required_context=['saml']),
            TestDefinition("regex_audience", MongoTestSuite.verify_audience_url_pattern,
                           dependencies=['exists_audience'],
                           required_context=['saml']),
            TestDefinition("exists_comparison_audience", MongoTestSuite.verify_audience_comparison_exists,
                           dependencies=['regex_audience'],
                           required_context=['comparison_values']),
            TestDefinition("match_audience", MongoTestSuite.verify_audience_url,
                           dependencies=['exists_comparison_audience'],
                           required_context=['saml', 'comparison_values']),

            # ACS URL tests
            TestDefinition("exists_acs", MongoTestSuite.verify_assertion_consumer_service_url_exists,
                           required_context=['saml']),
            TestDefinition("regex_acs", MongoTestSuite.verify_assertion_consumer_service_url_pattern,
                           dependencies=['exists_acs'],
                           required_context=['saml']),
            TestDefinition("exists_comparison_acs",
                           MongoTestSuite.verify_assertion_consumer_service_url_comparison_exists,
                           dependencies=['regex_acs'],
                           required_context=['comparison_values']),
            TestDefinition("match_acs", MongoTestSuite.verify_assertion_consumer_service_url,
                           dependencies=['exists_comparison_acs'],
                           required_context=['saml', 'comparison_values']),

            # Encryption algorithm tests
            TestDefinition("exists_encryption", MongoTestSuite.verify_encryption_algorithm_exists,
                           required_context=['saml']),
            TestDefinition("regex_encryption", MongoTestSuite.verify_encryption_algorithm_pattern,
                           dependencies=['exists_encryption'],
                           required_context=['saml']),
            TestDefinition("exists_comparison_encryption",
                           MongoTestSuite.verify_encryption_algorithm_comparison_exists,
                           dependencies=['regex_encryption'],
                           required_context=['comparison_values']),
            TestDefinition("match_encryption", MongoTestSuite.verify_encryption_algorithm,
                           dependencies=['exists_comparison_encryption'],
                           required_context=['saml', 'comparison_values']),
        ]
        return tests

    def get_list_of_mongo_tests(self):
        """
        Get name of tests in order listed. Useful for compiling reports.

        Returns:
            (`list` of `basestring`) test titles in order
        """
        return [test.title for test in self._tests]

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

    # Issuer URI tests
    @staticmethod
    def verify_issuer_exists(context):
        """
        Checks if Issuer URI was found in the SAML response.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if found, False otherwise
        """
        return context.get('saml').get_issuer_uri() is not None

    @staticmethod
    def verify_issuer_comparison_exists(context):
        """
        Checks if there is a comparison value for the Issuer URI.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if a comparison value exists, False otherwise
        """
        return context.get('comparison_values').get_parsed_value('issuer') is not None

    @staticmethod
    def verify_issuer(context):
        """
        Checks Issuer URI against expected value

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if they match, False otherwise
        """
        return context.get('saml').get_issuer_uri() == context.get('comparison_values').get_parsed_value('issuer')

    @staticmethod
    def verify_issuer_pattern(context):
        """
        Checks if Issuer URI matches the expected regular expression

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return MongoTestSuite._matches_regex(UserInputValidator().get_validation_regex('issuer'),
                                             context.get('saml').get_issuer_uri())

    # Audience URL tests
    @staticmethod
    def verify_audience_url_exists(context):
        """
        Checks if Audience URL was found in the SAML response.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if found, False otherwise
        """
        return context.get('saml').get_audience_url() is not None

    @staticmethod
    def verify_audience_comparison_exists(context):
        """
        Checks if there is a comparison value for the Audience URL.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if a comparison value exists, False otherwise
        """
        return context.get('comparison_values').get_parsed_value('audience') is not None

    @staticmethod
    def verify_audience_url(context):
        """
        Checks Audience URL against expected value

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if they match, False otherwise
        """
        return context.get('saml').get_audience_url() == \
               context.get('comparison_values').get_parsed_value('audience')

    @staticmethod
    def verify_audience_url_pattern(context):
        """
        Checks if Audience URL matches the expected regular expression

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return MongoTestSuite._matches_regex(UserInputValidator().get_validation_regex('audience'),
                                             context.get('saml').get_audience_url())

    # Assertion Consumer Service URL tests
    @staticmethod
    def verify_assertion_consumer_service_url_exists(context):
        """
        Checks if Assertion Consumer Service URL was found in the SAML response.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if found, False otherwise
        """
        return context.get('saml').get_assertion_consumer_service_url() is not None

    @staticmethod
    def verify_assertion_consumer_service_url_comparison_exists(context):
        """
        Checks if there is a comparison value for the Assertion Consumer Service URL.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if a comparison value exists, False otherwise
        """
        return context.get('comparison_values').get_parsed_value('acs') is not None

    @staticmethod
    def verify_assertion_consumer_service_url(context):
        """
        Checks Assertion Consumer Service URL against expected value

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if they match, False otherwise
        """
        return context.get('saml').get_assertion_consumer_service_url() == \
               context.get('comparison_values').get_parsed_value('acs')

    @staticmethod
    def verify_assertion_consumer_service_url_pattern(context):
        """
        Checks if Assertion Consumer Service URL matches the expected regular expression

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return MongoTestSuite._matches_regex(UserInputValidator().get_validation_regex('acs'),
                                             context.get('saml').get_assertion_consumer_service_url())

    # Encryption algorithm tests
    @staticmethod
    def verify_encryption_algorithm_exists(context):
        """
        Checks if encryption algorithm was found in the SAML response.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if found, False otherwise
        """
        return context.get('saml').get_encryption_algorithm() is not None

    @staticmethod
    def verify_encryption_algorithm_comparison_exists(context):
        """
        Checks if there is a comparison value for the Assertion Consumer Service URL.

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if a comparison value exists, False otherwise
        """
        return context.get('comparison_values').get_parsed_value('encryption') is not None

    @staticmethod
    def verify_encryption_algorithm(context):
        """
        Checks encryption algorithm against expected value

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if they match, False otherwise
        """

        # expected encryption algorithm format expected to be "SHA1" or "SHA256"
        return context.get('saml').get_encryption_algorithm() == \
               context.get('comparison_values').get_parsed_value('encryption')

    @staticmethod
    def verify_encryption_algorithm_pattern(context):
        """
        Checks if encryption algorithm matches the expected regular expression

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return MongoTestSuite._matches_regex(UserInputValidator().get_validation_regex('encryption'),
                                             context.get('saml').get_encryption_algorithm())

    # Name ID and format tests
    @staticmethod
    def verify_name_id(context):
        """
        Checks Name ID against expected value (case-insensitive)

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if they match, False otherwise
        """
        return context.get('saml').get_subject_name_id().lower() == \
               context.get('comparison_values').get_parsed_value('email').lower()

    @staticmethod
    def verify_name_id_exists(context):
        """
        Checks if Name ID exists in the SAML response

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if present, False otherwise
        """
        return context.get('saml').get_subject_name_id() is not None

    @staticmethod
    def verify_name_id_pattern(context):
        """
        Checks if Name ID matches the expected regular expression

        Args:
            context (dict): test context dictionary

        Returns:
            (bool) True if matches the regex, False otherwise
        """
        return MongoTestSuite._matches_regex(UserInputValidator().get_validation_regex('email'),
                                             context.get('saml').get_subject_name_id())

    @staticmethod
    def verify_name_id_format_exists(context):
        """
        Checks if Name ID Format was found in the SAML response.

        Returns:
            (bool) True if found, False otherwise
        """
        return context.get('saml').get_subject_name_id_format() is not None

    @staticmethod
    def verify_name_id_format(context):
        """
        Checks if Name ID format is one of the valid valuesI

        Returns:
            (bool) True if a valid value, False otherwise
        """
        return context.get('saml').get_subject_name_id_format() in MongoTestSuite.VALID_NAME_ID_FORMATS

    # Claim attribute tests
    @staticmethod
    def verify_all_required_attributes_exist(context):
        """
        Check if SAML response has all required attributes.

        Returns:
            (bool) true if all required attributes are in SAML response, false otherwise
        """
        saml_attributes = context.get('saml').get_attributes() or dict()
        return all(attribute_name in saml_attributes
                   for attribute_name in MongoTestSuite.REQUIRED_CLAIMS)

    @staticmethod
    def verify_first_name_exists(context):
        """
        Check if SAML response has 'firstName' claims attribute

        Returns:
            (bool) true if attribute is in SAML response, false otherwise
        """
        return 'firstName' in (context.get('saml').get_attributes() or dict())

    @staticmethod
    def verify_first_name_pattern(context):
        """
        Check if 'firstName' claims attribute matches regex pattern

        Returns:
            (bool) true if matches, false otherwise
        """
        return MongoTestSuite._matches_regex(
            UserInputValidator().get_validation_regex('firstName'),
            context.get('saml').get_attributes().get('firstName')
        )

    @staticmethod
    def verify_first_name_comparison_exists(context):
        """
        Check if 'firstName' claims attribute has a comparison value entered

        Returns:
            (bool) true if comparison value exists, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('firstName') is not None

    @staticmethod
    def verify_first_name(context):
        """
        Check if 'firstName' claims attribute matches comparison value entered (case-insensitive)

        Returns:
            (bool) true if matches, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('firstName').lower() == \
               context.get('saml').get_attributes().get('firstName').lower()

    @staticmethod
    def verify_last_name_exists(context):
        """
        Check if SAML response has 'lastName' claims attribute

        Returns:
            (bool) true if attribute is in SAML response, false otherwise
        """
        return 'lastName' in (context.get('saml').get_attributes() or dict())

    @staticmethod
    def verify_last_name_pattern(context):
        """
        Check if 'lastName' claims attribute matches regex pattern

        Returns:
            (bool) true if matches, false otherwise
        """
        return MongoTestSuite._matches_regex(
            UserInputValidator().get_validation_regex('lastName'),
            context.get('saml').get_attributes().get('lastName')
        )

    @staticmethod
    def verify_last_name_comparison_exists(context):
        """
        Check if 'lastName' claims attribute has a comparison value entered

        Returns:
            (bool) true if comparison value exists, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('lastName') is not None

    @staticmethod
    def verify_last_name(context):
        """
        Check if 'lastName' claims attribute matches comparison value entered (case-insensitive)

        Returns:
            (bool) true if matches, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('lastName').lower() == \
               context.get('saml').get_attributes().get('lastName').lower()

    @staticmethod
    def verify_email_exists(context):
        """
        Check if SAML response has 'email' claims attribute

        Returns:
            (bool) true if attribute is in SAML response, false otherwise
        """
        return 'email' in (context.get('saml').get_attributes() or dict())

    @staticmethod
    def verify_email_pattern(context):
        """
        Check if 'email' claims attribute matches regex pattern

        Returns:
            (bool) true if matches, false otherwise
        """
        return MongoTestSuite._matches_regex(
            UserInputValidator().get_validation_regex('email'),
            context.get('saml').get_attributes().get('email')
        )

    @staticmethod
    def verify_email_comparison_exists(context):
        """
        Check if 'email' claims attribute has a comparison value entered

        Returns:
            (bool) true if comparison value exists, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('email') is not None

    @staticmethod
    def verify_email(context):
        """
        Check if 'email' claims attribute matches comparison value entered (case-insensitive)

        Returns:
            (bool) true if matches, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('email').lower() == \
               context.get('saml').get_attributes().get('email').lower()

    @staticmethod
    def verify_member_of_exists(context):
        """
        Check if SAML response has 'memberOf' claims attribute

        Returns:
            (bool) true if attribute is in SAML response, false otherwise
        """
        return 'memberOf' in (context.get('saml').get_attributes() or dict())

    @staticmethod
    def verify_member_of_not_empty(context):
        """
        Check if 'memberOf' claims attribute is not empty.

        Returns:
            (bool) true if attribute is not empty, false otherwise
        """
        return len(context.get('saml').get_attributes().get('memberOf', [])) != 0

    @staticmethod
    def verify_member_of_pattern(context):
        """
        Check if all values in 'memberOf' claims attribute matches regex pattern

        Returns:
            (bool) true if matches, false otherwise
        """
        return all(
            MongoTestSuite._matches_regex(
                UserInputValidator().get_validation_regex('memberOf'), value
            ) for value in context.get('saml').get_attributes().get('memberOf', [])
        )

    @staticmethod
    def verify_member_of_is_expected(context):
        """
        Check if 'memberOf' claims attribute is in SAML response if customer
        expects to do role mapping.

        Returns:
            (bool) true if attribute exists and customer expects it, false otherwise
        """
        return not context.get('comparison_values').get_parsed_value('role_mapping_expected', False)

    @staticmethod
    def verify_member_of_comparison_exists(context):
        """
        Check if 'memberOf' claims attribute has a comparison value entered

        Returns:
            (bool) true if comparison value exists, false otherwise
        """
        return context.get('comparison_values').get_parsed_value('memberOf') is not None

    @staticmethod
    def verify_member_of(context):
        """
        Check if 'memberOf' claims attribute contains all comparison values entered

        Returns:
            (bool) true if matches, false otherwise
        """
        member_of_groups = context.get('saml').get_attributes().get('memberOf', [])
        return all(
            group in member_of_groups
            for group in context.get('comparison_values').get_parsed_value('memberOf', [])
        )

    # Name ID, email, and domain tests
    @staticmethod
    def verify_name_id_and_email_are_the_same(context):
        """
        Check if Name ID and email values from SAML response match (case-insensitive). This is not
        a hard requirement, but is typical and a mismatch may indicate an incorrect
        configuration.

        Returns:
            (bool) True if both values are present in the SAML response and match
        """
        # Not a requirement, but may indicate that a setting is incorrect
        name_id = context.get('saml').get_subject_name_id()
        email = context.get('saml').get_attributes().get('email')

        return name_id.lower() == email.lower()

    @staticmethod
    def verify_domain_comparison_exists(context):
        """
        Checks if a domain was specified for comparison

        Returns:
            (bool) True if a comparison exists, False otherwise
        """
        return context.get('comparison_values').get_parsed_value('domains') is not None

    @staticmethod
    def verify_domain_in_name_id(context):
        """
        Checks if Name ID contains one of the federated domains specified

        Returns:
            (bool) True if Name ID ends with one of the domains, False otherwise
        """
        return any(context.get('saml').get_subject_name_id().lower().endswith('@' + domain)
                   for domain in context.get('comparison_values').get_parsed_value('domains'))

    @staticmethod
    def verify_domain_in_email(context):
        """
        Checks if email attribute contains one of the federated domains specified

        Returns:
            (bool) True if email contains ends with one of the domains, False otherwise
        """
        return any(context.get('saml').get_attributes().get('email').lower().endswith('@' + domain)
                   for domain in context.get('comparison_values').get_parsed_value('domains'))

    @staticmethod
    def verify_domain_in_comparison_email(context):
        """
        Checks if the email value entered for comparison contains one of the
        federated domains specified

        Returns:
            (bool) True if email contains ends with one of the domains, False otherwise
        """
        return any(context.get('comparison_values').get_parsed_value('email').lower().endswith('@' + domain)
                   for domain in context.get('comparison_values').get_parsed_value('domains'))


class ValidationReport:
    """
    Generate validation report text for tests that fail.

    All future tests that need reporting should be added in this class.
    """
    def __init__(self, saml, comparison_values):
        """
        Build reporter object.

        Args:
            saml (BaseSamlParser): parsed SAML data
            comparison_values (MongoFederationConfig): comparison data
        """
        self._saml = saml
        self._comparison_values = comparison_values
        self._messages = None
        self._compile_messages()

    def get_all_messages(self):
        """
        Shows all possible messages that can be reported.

        Returns:
            (dict) messages keyed by test name
        """
        return self._messages

    def get_messages_by_name(self, tests):
        """
        Get report messages for the tests named.

        Args:
            tests (`list` of `basestring` or `TestDefinition`): tests on which
                reporting is to be done

        Returns:
            (dict) messages for the tests listed, keyed by value in list
        """
        return {test: self._messages.get(test, "") for test in tests}

    # These classes are for generating templated text for claim attributes
    @staticmethod
    def _get_claim_attribute_exist(attribute_name):
        return f"The required '{attribute_name}' claim attribute is missing " + \
               "or is misspelled (case matters!)"

    def _get_claim_attribute_regex(self, attribute_name):
        return f"The required '{attribute_name}' claim attribute does not " + \
               "appear to be formatted correctly.\nValue: " + \
               f"{self._saml.get_attributes().get(attribute_name)}"

    def _get_claim_attribute_mismatch(self, attribute_name):
        return f"The required '{attribute_name}' claim attribute does not match " + \
               "the value entered for comparison." + \
               f"\nSAML value: {self._saml.get_attributes().get(attribute_name)}" + \
               f"\nSpecified comparison value: {self._comparison_values.get_parsed_value(attribute_name)}" + \
               "\n\nGenerally, this means that the identity provider configuration needs\n" + \
               "to be reconfigured to match the expected values"

    @staticmethod
    def _print_a_list(template_string, list_contents):
        """
        Outputs a list of items based on a template. For example:
        if `template_string` is `"\n- {}"` and `list_contents` contains
        `['a', 'b', 'c']`, the outputted string will be `\n- a\n- b\n- c`.

        Args:
            template_string (basestring): template to repeat. Must have exactly one `{}` to
                be replaced
            list_contents (iterable): values to replace in template string

        Returns:
            (basestring) string that represents item list
        """
        full_string = template_string * len(list_contents)
        return full_string.format(*list_contents)

    def _compile_messages(self):
        """
        Generates messages for failed tests based on provided SAML and comparison data.

        Any future tests that require a report be generated should they fail should have
        an entry added to the `messages` dict with the test name as the key.

        Any templated text can be added as class functions.

        Returns:
            None
        """
        messages = {
            # Name ID tests
            'exists_name_id':
                f"The Name ID is missing from the SAML Subject.\n"
                f"Please be sure the customer's identity provider is\n"
                f"emitting this attribute (it is not emitted by default for Microsoft ADFS)",
            'regex_name_id':
                f"The Name ID does not appear to be an email address.\n"
                f"Name ID: {self._saml.get_subject_name_id()}",

            # Name ID Format tests
            'exists_name_id_format':
                "The Name ID format could not be parsed from the SAML response.",
            'regex_name_id_format':
                f"The Name ID format is not an acceptable format.\n" +
                f"SAML value: {self._saml.get_subject_name_id_format()}\n" +
                f"Acceptable formats:" +
                self._print_a_list("\n - {}", MongoTestSuite.VALID_NAME_ID_FORMATS),

            # Claim attribute tests
            'exists_all_required_attributes': "One or more of the required claim attributes are "
                                              "missing from the SAML response.\nThis should not cause a problem "
                                              "for users who log in using federation but already have a MongoDB "
                                              "Cloud account,\nbut will cause errors for any new users that attempt "
                                              "to authenticate.",
            'exists_first_name': self._get_claim_attribute_exist('firstName'),
            'regex_first_name': self._get_claim_attribute_regex('firstName'),
            'compare_first_name': self._get_claim_attribute_mismatch("firstName"),
            'exists_last_name': self._get_claim_attribute_exist('lastName'),
            'regex_last_name': self._get_claim_attribute_regex('lastName'),
            'compare_last_name': self._get_claim_attribute_mismatch("lastName"),
            'exists_email': self._get_claim_attribute_exist('email'),
            'regex_email': self._get_claim_attribute_regex('email'),
            'compare_email': self._get_claim_attribute_mismatch("email"),

            # Role mapping tests
            'member_of_is_expected':
                "The customer expects to use role mapping, but the 'memberOf' attribute\n" +
                "is missing from the SAML response. The identity provider needs to be configured\n" +
                "to send the group names. It is possible that the user is a member of no groups and\n" +
                "so the identity provider may have omitted the attribute altogether.",
            'regex_member_of': self._get_claim_attribute_regex('memberOf'),
            'compare_member_of':
                f"The optional 'memberOf' claim attribute is missing one or more values entered for comparison." + \
                f"\nSAML value:" + self._print_a_list("\n - {}", self._saml.get_attributes().get('memberOf', [])) + \
                f"\nSpecified comparison value:" + self._print_a_list(
                    "\n - {}", self._comparison_values.get_parsed_value('memberOf', [])) + \
                "\n\nGenerally, this means that the user's account in the customer Active Directory\n" + \
                "needs to be added to the correct group.",

            # Federated domain tests
            'compare_domain_email':
                "The 'email' attribute does not contain one of the federated domains specified:\n" +
                f"SAML 'email' attribute value: {self._saml.get_subject_name_id()}\n" +
                f"Specified valid domains:" +
                self._print_a_list("\n - {}", self._comparison_values.get_parsed_value('domains', [])) +
                "\n\nIf the 'email' attribute does not contain a verified domain name, it may be because\n" +
                "the source Active Directory field does not contain the user's e-mail address.\n" +
                "The source field may contain an internal username or other value instead.\n" +
                "This is not necessarily an error, but may indicate there is a misconfiguration.\n" +
                "The value in Name ID will be the user's login username and the value in the\n" +
                "email attribute will be the address where the user receives email messages.\n" +
                "So only the Name ID must contain the domain.",
            'compare_domain_comparison_email':
                "The specified comparison e-mail value does not contain\n" +
                "one of the federated domains specified:\n" +
                f"Specified e-mail value: {self._comparison_values.get_parsed_value('email')}\n" +
                f"Specified valid domains:" +
                self._print_a_list("\n - {}", self._comparison_values.get_parsed_value('domains', [])) +
                "\n\nIf the e-mail specified is the user's MongoDB username, then the Atlas\n" +
                "identity provider configuration likely has the incorrect domain(s) verified.",
            'compare_domain_name_id':
                "The Name ID does not contain one of the federated domains specified:\n" +
                f"Name ID value: {self._saml.get_subject_name_id()}\n" +
                f"Specified valid domains:" +
                self._print_a_list("\n - {}", self._comparison_values.get_parsed_value('domains', [])) +
                "\n\nIf the Name ID does not contain a verified domain name, it may be because\n" +
                "the source Active Directory field does not contain the user's e-mail address.\n" +
                "The source field may contain an internal username or other value instead.",

            # Email and Name ID tests
            'compare_email_name_id':
                "The Name ID does not match the provided e-mail value:\n" +
                f"Name ID value: {self._saml.get_subject_name_id()}\n" +
                f"Specified email value: {self._comparison_values.get_parsed_value('email')}" +
                "\n\nThis is not necessarily an error, but may indicate there is a misconfiguration.\n" +
                "The value in Name ID will be the user's login username and the value in the\n" +
                "email attribute will be the address where the user receives email messages.",
            'match_name_id_email_in_saml':
                "The Name ID and email attributes are not the same. This is not\n" +
                "necessarily an error, but may indicate there is a misconfiguration.\n" +
                "The value in Name ID will be the user's login username and the value in the\n" +
                "email attribute will be the address where the user receives email messages.",

            # Issuer URI tests
            'exists_issuer':
                "The Issuer URI could not be parsed from the SAML response." +
                "\nCannot run any verification tests for this parameter.",
            'regex_issuer':
                f"The Issuer URI does not match the anticipated pattern.\n" +
                f"Issuer URI: {self._saml.get_issuer_uri()}",
            'match_issuer':
                "The Issuer URI in the SAML response does not match the specified comparison value:\n" +
                f"SAML value: {self._saml.get_issuer_uri()}\n" +
                f"Specified comparison value: {self._comparison_values.get_parsed_value('issuer')}" +
                "\n\nGenerally, this means that the Atlas configuration needs " +
                "to be set to match the SAML value",

            # Audience URL tests
            'exists_audience':
                "The Audience URL could not be parsed from the SAML response." +
                "\nCannot run any verification tests for this parameter.",
            'regex_audience':
                f"The Audience URL does not match the anticipated pattern.\n" +
                f"Audience URL: {self._saml.get_audience_url()}",
            'match_audience':
                "The Audience URL in the SAML response does not match the specified comparison value:\n" +
                f"SAML value: {self._saml.get_audience_url()}\n" +
                f"Specified comparison value: {self._comparison_values.get_parsed_value('audience')}" +
                "\n\nGenerally, this means that the Atlas configuration needs " +
                "to be set to match the SAML value",

            # ACS URL tests
            'exists_acs':
                "The Assertion Consumer Service URL could not be parsed from the SAML response." +
                "\nCannot run any verification tests for this parameter.",
            'regex_acs':
                f"The Assertion Consumer Service URL does not match the anticipated pattern.\n" +
                f"ACS URL: {self._saml.get_assertion_consumer_service_url()}",
            'match_acs':
                "The Assertion Consumer Service URL in the SAML response does not match the " +
                "specified comparison value:\n" +
                f"SAML value: {self._saml.get_assertion_consumer_service_url()}\n" +
                f"Specified comparison value: {self._comparison_values.get_parsed_value('acs')}" +
                "\n\nThis means that the identity provider configuration needs\n" +
                "to be reconfigured to match the expected value",

            # Encryption algorithm tests
            'exists_encryption':
                "The encryption algorithm could not be parsed from the SAML response." +
                "\nCannot run any verification tests for this parameter.",
            'regex_encryption':
                f"The encryption algorithm does not match the anticipated pattern.\n" +
                f"Encryption Algorithm: {self._saml.get_encryption_algorithm()}",
            'match_encryption':
                "The encryption algorithm for the SAML response does not " +
                "match the specified comparison value:\n" +
                f"SAML value: {self._saml.get_encryption_algorithm()}\n" +
                f"Specified comparison value: " +
                f"{self._comparison_values.get_parsed_value('encryption')}" +
                "\n\nGenerally, this means that the Atlas configuration needs " +
                "to be set to match the SAML value"
        }

        self._messages = messages

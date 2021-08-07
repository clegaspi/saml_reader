import re

"""Regular expression to match (most) valid e-mail addresses"""
EMAIL_REGEX_MATCH = r"\b(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b"


class _NullUserInput:
    pass


class UserInputValidator:
    def __init__(self):
        # Regular expressions to validate SAML fields and claim attributes
        self._regex_by_attribute = {
            'firstName': r'^\s*\S+.*$',
            'lastName': r'^\s*\S+.*$',
            'email': r"\b(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b",
            'issuer': r'^\s*\S+.*$',
            'acs': r'^https:\/\/auth\.mongodb\.com\/sso\/saml2\/[a-z0-9A-Z]{20}$',
            'audience': r'^https:\/\/www\.okta\.com\/saml2\/service-provider\/[a-z]{20}$',
            'encryption': r'^(?i)sha-?(1|256)$',
            'domains': r'^(?i)[A-Z0-9.-]+?\.[A-Z]{2,}$',
            'memberOf': r'^\s*\S+.*$',
            'role_mapping_expected': '^(?i)[YN]$'
        }

        self._func_by_attribute = {
            'cert_expiration': self._validate_cert_expiration
        }

    def __contains__(self, value):
        return value in self._regex_by_attribute or value in self._func_by_attribute

    def validate(self, attribute_name, value):
        if value == _NullUserInput:
            return True
        
        regex_valid = True
        func_valid = True

        if attribute_name in self._regex_by_attribute:
            regex_valid = bool(re.fullmatch(self._regex_by_attribute[attribute_name], value))
        if attribute_name in self._func_by_attribute:
            func_valid = bool(self._func_by_attribute[attribute_name](value))

        return regex_valid and func_valid

    def get_validation_regex(self, attribute_name):
        if attribute_name in self._regex_by_attribute:
            return self._regex_by_attribute[attribute_name]
        raise ValueError(f"Regex for attribute name '{attribute_name}' not found")

    def _validate_cert_expiration(self, value):
        return True


class UserInputParser:
    def __init__(self) -> None:
        self._validator = UserInputValidator()

        self._parsing_func_by_attribute = {
            'domains': lambda x: [v.strip().lower() for v in x],
            'encryption': lambda x: "SHA" + re.findall(
                self._validator.get_validation_regex('encryption'), x)[0],
            'firstName': lambda x: x.strip(),
            'lastName': lambda x: x.strip(),
            'email': lambda x: x.strip(),
            'role_mapping_expected': lambda x: x.upper() == 'Y'
        }

    def parse(self, attribute_name, value):
        if value == _NullUserInput or attribute_name not in self._parsing_func_by_attribute:
            return value
        return self._parsing_func_by_attribute[attribute_name](value)


class MongoComparisonValue:
    """
    Collects comparison value input from the user through stdin prompts
    """
    def __init__(self, name, prompt, multi_value=False, default=_NullUserInput):
        """
        Create a comparison value object for a given value type.

        Args:
            name (basestring): name of the input value, must be contained in UserInputValidator.
            prompt (basestring): the text with which to prompt the user during input
            multi_value (bool, optional): True if the user should be prompted for more than one input value,
                False will only prompt for one input value. Default: False (one input)
            default (object, optional): The default value to set if the user does not input anything. Default: None
        """
        self._validator = UserInputValidator()
        if name not in self._validator:
            raise ValueError(f"Unknown value name: {name}")
        self._name = name
        self._prompt = prompt
        self._value = _NullUserInput
        self._is_multivalued = multi_value
        if self._validator.validate(name, default):
            self._default = default
        else:
            raise ValueError(f"Invalid default value '{default}' for attribute '{name}'")

    def prompt_for_user_input(self):
        """
        Prompt user for input using stdin.

        Returns:
            (`basestring`, `list`, or `object`) The user input as a string or list, depending if multi-valued
                or the default value if no user input provided
        """
        if self._is_multivalued:
            user_input = self._get_multi_value()
        else:
            user_input = self._get_single_value()

        if user_input is _NullUserInput:
            self._value = self._default
        
        self._value = user_input

    def get_name(self):
        """
        Get value name

        Returns:
            (basestring) value name
        """
        return self._name

    def get_value(self):
        if self._value is _NullUserInput:
            raise ValueError("This value has not been gathered yet!")
        return self._value

    def set_value(self, value):
        if isinstance(value, list):
            value_list = value
        else:
            value_list = [value]
        if all(self._validator.validate(self._name, v) for v in value_list):
            self._value = value
        else:
            raise ValueError("Input did not pass validation")

    def is_null(self):
        return self._value is _NullUserInput

    def _get_single_value(self):
        """
        Prompt user for a single value with default prompt.

        Returns:
            (`basestring` or `object`) The user input as a string
                or the default value if no user input provided
        """
        return self._get_and_validate_user_input()

    def _get_multi_value(self):
        """
        Prompt user for a multiple values with a numbered prompt.

        Returns:
            (`list` or `object`) The user input as a list
                or the default value if no user input provided
        """
        input_to_store = []
        print(self._prompt)
        list_index = 1
        user_input = self._get_and_validate_user_input(prompt=f"{list_index}.")
        while user_input is not _NullUserInput:
            input_to_store.append(user_input)
            list_index += 1
            user_input = self._get_and_validate_user_input(prompt=f"{list_index}.")
        if not input_to_store:
            input_to_store = self._default

        return input_to_store

    def _get_and_validate_user_input(self, prompt=None):
        """
        Prompts user for input from stdin.

        Args:
            prompt (basestring, optional): The text to prompt the user with.
                Default: None (prompts with self._prompt)

        Returns:
            (`basestring`) the data input by the user. None if user inputs nothing.
        """
        if prompt is None:
            prompt = self._prompt

        if not re.match(r'.*\s$', prompt):
            # If the prompt doesn't end with a whitespace character, add a space for padding
            prompt += " "

        while True:
            user_input = input(prompt)
            if user_input:
                if self._validator.validate(self._name, user_input):
                    return user_input
                else:
                    print(f"Input did not pass validation. Try again or skip the value.")
            else:
                return _NullUserInput


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
                - `domains`: domain names associated with the identity provider, as a
                    string. Multiple domains separated by whitespace.
        """
        self._settings = dict()
        self._parser = UserInputParser()
        if kwargs:
            for name, value in kwargs.items():
                value_obj = MongoComparisonValue(name, "")
                try:
                    value_obj.set_value(value)
                except ValueError:
                    raise ValueError(f"Input for attribute {name} did not pass validation", name)
                self.set_value(value_obj)

    def get_parsed_value(self, value_name, default=None):
        """
        Get comparison value by name

        Args:
            value_name (basestring): name of comparison value keyword
            default (object, optional): the value returned if the comparison value is not populated. Default: None

        Returns:
            (`basestring` or `None`) comparison value, `None` if name does not exist
        """
        return self._settings.get(value_name, default)

    def set_values(self, value_list):
        if not all(isinstance(v, MongoComparisonValue) for v in value_list):
            raise TypeError("All values must be of type MongoComparisonValue")

        for value_obj in value_list:
            name = value_obj.get_name()
            value = value_obj.get_value()
            self._settings[name] = self._parser.parse(name, value)

    def set_value(self, value):
        if not isinstance(value, MongoComparisonValue):
            raise TypeError("Value must be of type MongoComparisonValue")
        self.set_values([value])

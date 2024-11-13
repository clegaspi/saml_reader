"""
Custom errors for SAML parsing
"""


class SamlError(Exception):
    """
    Base exception type to require capture of parser type that raised the exception
    """

    def __init__(self, message, parser):
        """
        Create exception based on parser that raised it

        Args:
            message (basestring): exception message to show
            parser (basestring): type of parser that raised the exception.
                Should be one of the following:
                - `'strict'`: standard XML parser
                - `'relaxed'`: relaxed XML parser
                - `'regex'`: regular expression-based parser
        """
        self.parser = parser
        super().__init__(message)


class SamlResponseEncryptedError(SamlError):
    """
    Custom exception type raised when SAML responses are encrypted
    """

    pass


class SamlParsingError(SamlError):
    """
    Custom exception type raised when SAML response could not be parsed by this parser
    """

    pass


class IsASamlRequest(SamlError):
    """
    Custom exception type raised when SAML data is actually a request and not a response
    """

    pass


class DataTypeInvalid(Exception):
    """
    Custom exception raised when the input data doesn't appear to match the specified input type
    """

    pass

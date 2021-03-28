"""
This module implements features related to parsing har files and retrieving the SAML response(s)
contained within.
"""

import json
from urllib.parse import unquote
from datetime import datetime
from enum import Enum

import haralyzer


class HarParsingError(Exception):
    """
    Custom exception raised when we get any error from the HAR parser
    """
    pass


class NoSAMLResponseFound(Exception):
    """
    Custom exception if we don't find a SAML response
    """
    pass


class HarParser(object):
    """
    Wrapper around haralyzer package to read HAR file contents and retrieve SAML responses.
    """
    def __init__(self, data):
        """
        Create object containing raw HAR data.

        Args:
            data (basestring): Raw HAR data as JSON-string
        """
        try:
            self.data = json.loads(data)
        except json.JSONDecodeError:
            raise HarParsingError("Problem reading HAR JSON data")

        self.responses = self.__parse(self.data)
        # Sort responses newest to oldest
        self.responses.sort(reverse=True, key=lambda x: x.date)

    @staticmethod
    def __parse(raw_json):
        """
        Parses the raw HAR data and returns SAML response data.

        Returns:
            (`list` of `RawSamlData`): SAML response data found in HAR file
        """
        try:
            parsed_har = haralyzer.HarParser(raw_json)
        except Exception:
            # This is a wide catch-all
            raise HarParsingError("Could not parse the HAR data")

        responses = []
        for page in parsed_har.pages:
            for post in page.post_requests:
                timestamp = post['startedDateTime']
                url = post.get('request', {}).get('url', "")
                for param in post.get('request', {}).get('postData', {}).get('params', []):
                    if param['name'] == 'SAMLResponse':
                        unencoded_response = unquote(param['value'])
                        responses.append(
                            RawSamlData('response', unencoded_response, timestamp, url)
                        )

        if not responses:
            raise NoSAMLResponseFound("No SAML response found in the HAR file")

        return responses

    def get_raw_saml_response(self):
        """
        Returns the most recent SAML response in the HAR data (if there are multiple) as
        url-decoded base64-encoded string.

        Returns:
            (basestring) Raw SAML data as base64-encoded string

        """
        return self.responses[0].saml_string

    def contains_multiple_responses(self):
        """
        Checks if the HAR data contained multiple SAML responses.

        Returns:
            (bool) True if contained more than one SAML response. False otherwise.
        """
        return len(self.responses) > 1

    @classmethod
    def from_file(cls, filename):
        """
        Read HAR file to create parser object

        Args:
            filename (basestring): path to HAR file

        Returns:
            (HarParser) parser object
        """
        with open(filename, 'r') as f:
            return cls(f.read())


class RawSamlData:
    """
    Simple data structure for holding raw SAML data and some metadata
    """
    class _SamlDataType(Enum):
        """
        Enumeration of possible SAML data types
        """
        RESPONSE = 0
        REQUEST = 1

    def __init__(self, data_type, saml_string, date, url):
        """
        Create data structure object

        Args:
            data_type (basestring): Type of SAML data ('request' or 'response')
            saml_string (basestring): URL-decoded base64 string containing SAML data
            date (basestring): timestamp of request from HAR file, formatted "2019-11-04T10:00:00.000-08:00"
            url (basestring): destination URL of the SAML data
        """
        self.data_type = self._SamlDataType[data_type.upper()]
        self.saml_string = saml_string
        if ":" == date[-3:-2]:
            date = date[:-3] + date[-2:]
        self.date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f%z")
        self.url = url

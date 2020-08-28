"""
This module implements features related to parsing har files and retrieving the SAML response(s)
contained within.
"""

import json
from urllib.parse import unquote

import haralyzer


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
        # TODO: Consider parsing this upon creation and writing a getter for SAML response(s)
        #       to wrap the haralyzer package more thoroughly
        self.data = json.loads(data)
        self.parsed_data = None

    def parse(self):
        """
        Parses the raw HAR data and stores it in the object.

        Returns:
            (basestring): SAML response as base64 string
        """
        parsed_har = haralyzer.HarParser(self.data)
        responses = []
        for page in parsed_har.pages:
            for post in page.post_requests:
                if 'params' not in post['request']['postData']:
                    continue
                for param in post['request']['postData']['params']:
                    if param['name'] == 'SAMLResponse':
                        responses.append(param['value'])

        if len(responses) > 1:
            print("Multiple SAML responses found. Using the first one.")

        if not responses:
            raise Exception("No SAML response found in the HAR file")

        self.parsed_data = unquote(responses[0])
        return self.parsed_data

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

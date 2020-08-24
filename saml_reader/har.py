import json
from urllib.parse import unquote

import haralyzer


class HarParser(object):
    def __init__(self, data):
        self.data = json.loads(data)
        self.parsed_data = None

    def parse(self):
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
        with open(filename, 'r') as f:
            return cls(f.read())

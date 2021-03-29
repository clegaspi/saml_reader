import unittest
import os
import json
from datetime import datetime
from urllib.parse import unquote

from saml_reader.har import HarParser, HarParsingError, NoSAMLResponseFound, RawSamlData

# The HAR data included here has been constructed from an actual login session, but
# has been highly redacted. The infrastructure that generated this SAML data has been
# torn down and is no longer usable.
TEST_DATA = {
    'multiple_requests_and_responses': './tests/data/redacted_saml.har',
    'two_responses': './tests/data/redacted_responses.har',
    'one_response': './tests/data/redacted_oneresponse.har',
    'two_requests': './tests/data/redacted_requests.har',
    'no_data': './tests/data/redacted_nodata.har'
}


class HarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing_files = [data for data, file in TEST_DATA.items() if not os.path.exists(file)]
        if missing_files:
            raise FileNotFoundError(
                f"HAR data for testing not found! Missing:" + "\n- ".join(missing_files)
            )
        with open(TEST_DATA['multiple_requests_and_responses'], 'r') as f:
            cls.har_data_full = f.read()
        with open(TEST_DATA['no_data'], 'r') as f:
            cls.har_data_no_saml = f.read()
        with open(TEST_DATA['two_responses'], 'r') as f:
            cls.har_data_responses = f.read()
        with open(TEST_DATA['one_response'], 'r') as f:
            cls.har_data_one_response = f.read()
        with open(TEST_DATA['two_requests'], 'r') as f:
            cls.har_data_requests = f.read()

    def test_load_valid_har_both_saml_types(self):
        har = HarParser(self.har_data_full)
        self.assertIsInstance(har, HarParser)

    def test_load_valid_har_multiple_responses_only(self):
        har = HarParser(self.har_data_responses)
        self.assertIsInstance(har, HarParser)

    def test_load_valid_har_multiple_requests_only(self):
        with self.assertRaises(NoSAMLResponseFound):
            _ = HarParser(self.har_data_requests)

    def test_load_valid_har_no_saml_data(self):
        with self.assertRaises(NoSAMLResponseFound):
            _ = HarParser(self.har_data_no_saml)

    def test_load_valid_har_one_response(self):
        har = HarParser(self.har_data_one_response)
        self.assertIsInstance(har, HarParser)

    def test_load_invalid_har(self):
        with self.assertRaises(HarParsingError):
            _ = HarParser("This is invalid JSON")
        with self.assertRaises(HarParsingError):
            _ = HarParser(json.dumps({'value': 'This is valid JSON, but not a HAR file'}))

    def test_load_from_file(self):
        har = HarParser.from_file(TEST_DATA['one_response'])
        self.assertIsInstance(har, HarParser)

    def test_detect_multiple_responses(self):
        # Positive test
        har = HarParser(self.har_data_responses)
        self.assertTrue(har.contains_multiple_responses())
        har = HarParser(self.har_data_full)
        self.assertTrue(har.contains_multiple_responses())

        # Negative test
        har = HarParser(self.har_data_one_response)
        self.assertFalse(har.contains_multiple_responses())

    def test_returns_most_recent_saml_response(self):
        # Gather timestamps from SAML responses and sort them to get most recent
        raw_json = json.loads(self.har_data_responses)
        timestamps = [x['startedDateTime'] for x in raw_json['log']['entries']]
        date_objects = [
            datetime.strptime("".join(x.rsplit(":", 1)), "%Y-%m-%dT%H:%M:%S.%f%z")
            for x in timestamps
        ]
        date_objects.sort(reverse=True)
        most_recent_timestamp = date_objects[0]

        # Get SAML data
        har = HarParser(self.har_data_responses)
        most_recent_response = [x.saml_string for x in har.responses if x.date == most_recent_timestamp]
        self.assertTrue(len(most_recent_response) == 1)
        returned_response = har.get_raw_saml_response()
        self.assertEqual(returned_response, most_recent_response[0])

    def test_create_raw_saml_response_data_structure(self):
        raw_json = json.loads(self.har_data_one_response)
        timestamp = raw_json['log']['entries'][0]['startedDateTime']
        date_object = datetime.strptime("".join(timestamp.rsplit(":", 1)), "%Y-%m-%dT%H:%M:%S.%f%z")
        url = raw_json['log']['entries'][0]['request']['url']
        saml_string = None
        for param in raw_json['log']['entries'][0]['request']['postData']['params']:
            if param['name'] == 'SAMLResponse':
                saml_string = unquote(param['value'])
        self.assertIsNotNone(saml_string)

        saml_object = RawSamlData('response', saml_string, timestamp, url)
        self.assertEqual(saml_object.data_type, RawSamlData._SamlDataType.RESPONSE)
        self.assertEqual(saml_object.url, url)
        self.assertEqual(saml_object.saml_string, saml_string)
        self.assertEqual(saml_object.date, date_object)

    def test_create_raw_saml_request_data_structure(self):
        raw_json = json.loads(self.har_data_requests)
        timestamp = raw_json['log']['entries'][0]['startedDateTime']
        date_object = datetime.strptime("".join(timestamp.rsplit(":", 1)), "%Y-%m-%dT%H:%M:%S.%f%z")
        url = raw_json['log']['entries'][0]['request']['url']
        saml_string = None
        for param in raw_json['log']['entries'][0]['request']['postData']['params']:
            if param['name'] == 'SAMLRequest':
                saml_string = unquote(param['value'])
        self.assertIsNotNone(saml_string)

        saml_object = RawSamlData('request', saml_string, timestamp, url)
        self.assertEqual(saml_object.data_type, RawSamlData._SamlDataType.REQUEST)
        self.assertEqual(saml_object.url, url)
        self.assertEqual(saml_object.saml_string, saml_string)
        self.assertEqual(saml_object.date, date_object)


if __name__ == '__main__':
    unittest.main()

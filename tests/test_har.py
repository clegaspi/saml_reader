import unittest
import os
import json

from saml_reader.har import HarParser, HarParsingError, NoSAMLResponseFound

# The HAR data included here has been constructed from an actual login session, but
# has been highly redacted. The infrastructure that generated this SAML data has been
# torn down and is no longer usable.
TEST_DATA = {
    'all_data': './tests/data/redacted_saml.har',
    'response': './tests/data/redacted_responses.har',
    'request': './tests/data/redacted_requests.har',
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
        with open(TEST_DATA['all_data'], 'r') as f:
            cls.har_data = f.read()
        with open(TEST_DATA['no_data'], 'r') as f:
            cls.har_data_no_saml = f.read()
        with open(TEST_DATA['response'], 'r') as f:
            cls.har_data_response = f.read()
        with open(TEST_DATA['request'], 'r') as f:
            cls.har_data_request = f.read()

    def test_load_valid_har_both_saml_types(self):
        _ = HarParser(self.har_data)

    def test_load_valid_har_responses_only(self):
        _ = HarParser(self.har_data_response)

    def test_load_valid_har_requests_only(self):
        with self.assertRaises(NoSAMLResponseFound):
            _ = HarParser(self.har_data_request)

    def test_load_valid_har_no_saml_data(self):
        with self.assertRaises(NoSAMLResponseFound):
            _ = HarParser(self.har_data_no_saml)

    def test_load_invalid_har(self):
        with self.assertRaises(HarParsingError):
            _ = HarParser("This is invalid JSON")
        with self.assertRaises(HarParsingError):
            _ = HarParser(json.dumps({'value': 'This is valid JSON, but not a HAR file'}))


if __name__ == '__main__':
    unittest.main()

import unittest
import os

from saml_reader.har import HarParser

# The HAR data included here has been constructed from an actual login session, but
# has been highly redacted. The infrastructure that generated this SAML data has been
# torn down and is no longer usable.
TEST_HAR_DATA = './tests/data/redacted.har'


class HarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not os.path.exists(TEST_HAR_DATA):
            raise FileNotFoundError(
                "HAR data for testing not found! Modify TEST_HAR_DATA with path to valid HAR file"
            )
        with open(TEST_HAR_DATA, 'r') as f:
            cls.har_data = f.read()

    def test_load_har(self):
        pass


if __name__ == '__main__':
    unittest.main()

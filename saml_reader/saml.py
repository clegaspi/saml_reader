from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.utils import OneLogin_Saml2_Utils as utils


class SamlParser(OneLogin_Saml2_Response):
    def __init__(self, response):
        # response should be base64 encoded
        super().__init__(None, response)

    @classmethod
    def from_xml(cls, xml):
        return cls(utils.b64encode(xml))

    def get_certificate(self):
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
        if result:
            return result[0].text
        raise Exception("Did not find certificate")

    def get_subject_nameid(self):
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            return result[0].text
        raise Exception("Did not find Name ID")

    def get_subject_nameid_format(self):
        result = self._OneLogin_Saml2_Response__query_assertion(
            '/saml:Subject/saml:NameID')
        if result:
            return result[0].attrib['Format']
        raise Exception("Did not find Name ID Format")

    def get_acs(self):
        result = self._OneLogin_Saml2_Response__query(
            '/samlp:Response')
        if result:
            return result[0].attrib['Destination']
        raise Exception("Did not find ACS")
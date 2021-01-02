from functools import partial
import re

from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from lxml import etree
from defusedxml.lxml import RestrictedElement

from saml_reader.saml.errors import SamlParsingError, SamlResponseEncryptedError, IsASamlRequest


class OLISamlParser(OneLogin_Saml2_Response):
    def __init__(self, response):
        """
        Build OneLogin object manually.

        Args:
            response (basestring): SAML data as stringified XML document
        """
        # This is basically a copy-paste of the parent class __init__()
        # with tweaks to handle the change in parser, etc.

        # These are copied from the parent class
        self.__error = None
        self.decrypted_document = None
        self.encrypted = None
        self.valid_scd_not_on_or_after = None

        # After this point, the logic is customized
        self.__settings = None
        self.response = response
        self.document = None
        self.used_relaxed_parser = False
        while self.document is None:
            try:
                self.document = OneLogin_Saml2_XML.to_etree(self.response)
            except etree.XMLSyntaxError:
                if self.used_relaxed_parser:
                    raise SamlParsingError("Could not parse the XML data",
                                           'relaxed' if self.used_relaxed_parser else 'strict')
                # Use a parser which attempts to recover bad XML
                relaxed_xml_parser = etree.XMLParser(recover=True, resolve_entities=False)
                lookup = etree.ElementDefaultClassLookup(element=RestrictedElement)
                relaxed_xml_parser.set_element_class_lookup(lookup)
                # Inject parser into the OLI class because there is no provided way to
                # change parser
                OneLogin_Saml2_XML._parse_etree = partial(OneLogin_Saml2_XML._parse_etree,
                                                          parser=relaxed_xml_parser)
                self.used_relaxed_parser = True
            except AttributeError as e:
                if e.args[0].endswith("'getroottree'"):
                    # Even the relaxed parser couldn't parse this. Parser fails.
                    raise SamlParsingError("Could not parse the XML data",
                                           'relaxed' if self.used_relaxed_parser else 'strict')
                else:
                    raise e

        if self.used_relaxed_parser:
            # If the parser was relaxed, want to make sure we brute-force check.
            encrypted_assertion_nodes = re.findall(r'</?(?:saml.?:)?EncryptedAssertion', self.response)
            saml_request_node = re.findall(r'<\/?(?:saml.{0,2}:)?AuthnRequest', self.response)
        else:
            encrypted_assertion_nodes = self.query('/samlp:Response/saml:EncryptedAssertion')
            saml_request_node = self.query('/samlp:AuthnRequest')
        if encrypted_assertion_nodes:
            raise SamlResponseEncryptedError("SAML response is encrypted. Cannot parse without key",
                                             'relaxed' if self.used_relaxed_parser else 'strict')
        if saml_request_node:
            raise IsASamlRequest("The SAML data contains a request and not a response",
                                 'relaxed' if self.used_relaxed_parser else 'strict')

    def query_assertion(self, path):
        return self._OneLogin_Saml2_Response__query_assertion(path)

    def query(self, path):
        return self._OneLogin_Saml2_Response__query(path)

"""
This file contains customized wrappers for several OneLogin SAML classes to expand
parsing ability and control errors raised.
"""

from collections import defaultdict
from functools import partial
import re

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from onelogin.saml2 import compat
from lxml import etree
from onelogin.saml2.xmlparser import RestrictedElement

from saml_reader.saml.errors import (
    SamlParsingError,
    SamlResponseEncryptedError,
    IsASamlRequest,
)


# noinspection PyMissingConstructor
class OLISamlParser(OneLogin_Saml2_Response):
    """
    Wrapper for OneLogin SAML parser to be able to handle malformed XML and return
    custom errors.
    """

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
                self.document = CustomXMLParser.parse(
                    self.response, relaxed=self.used_relaxed_parser
                )
            except SamlParsingError as e:
                if self.used_relaxed_parser:
                    raise e
                self.used_relaxed_parser = True

        if self.used_relaxed_parser:
            if isinstance(self.response, bytes):
                self.response = str(self.response, encoding="UTF-8")
            # If the parser was relaxed, want to make sure we brute-force check.
            encrypted_assertion_nodes = re.findall(
                r"</?(?:saml.?:)?EncryptedAssertion",
                self.response,
            )
            saml_request_node = re.findall(
                r"<\/?(?:saml.{0,2}:)?AuthnRequest",
                self.response,
            )
        else:
            encrypted_assertion_nodes = self.query(
                "/samlp:Response/saml:EncryptedAssertion"
            )
            saml_request_node = self.query("/samlp:AuthnRequest")

        if encrypted_assertion_nodes:
            raise SamlResponseEncryptedError(
                "SAML response is encrypted. Cannot parse without key",
                "relaxed" if self.used_relaxed_parser else "strict",
            )
        if saml_request_node:
            raise IsASamlRequest(
                "The SAML data contains a request and not a response",
                "relaxed" if self.used_relaxed_parser else "strict",
            )

    def get_attributes(self, mark_duplicate_attributes=False):
        """Get attributes from attribute statement.

        Args:
            mark_duplicate_attributes (bool, optional): True will return a second
            value which is a set of attribute names which are duplicated in the
            SAML data. Defaults to False.

        Returns:
            Union[Dict, Tuple[Dict, Set[str]]]: Attribute values, keyed by name. If
            `mark_duplicate_attributes=True`, a second value is returned as
            a set of strings with attribute values that are duplicated
        """
        # This is basically a copy-paste of the parent class get_attributes()
        # with tweaks to handle duplicate attributes
        attributes = defaultdict(list)
        duplicate_attributes = set()

        attribute_nodes = self.query_assertion(
            "/saml:AttributeStatement/saml:Attribute"
        )
        for attribute_node in attribute_nodes:
            attr_name = attribute_node.get("Name")
            if attr_name in attributes:
                duplicate_attributes.add(attr_name)
            for attr in attribute_node.iterchildren(
                "{%s}AttributeValue" % OneLogin_Saml2_Constants.NSMAP["saml"]
            ):
                attr_text = OneLogin_Saml2_XML.element_text(attr)
                if attr_text:
                    attr_text = attr_text.strip()
                    if attr_text:
                        attributes[attr_name].append(attr_text)

                # Parse any nested NameID children
                for nameid in attr.iterchildren(
                    "{%s}NameID" % OneLogin_Saml2_Constants.NSMAP["saml"]
                ):
                    attributes[attr_name].append(
                        {
                            "NameID": {
                                "Format": nameid.get("Format"),
                                "NameQualifier": nameid.get("NameQualifier"),
                                "value": nameid.text,
                            }
                        }
                    )
        if mark_duplicate_attributes:
            return {
                k: {"values": v, "is_duplicate": k in duplicate_attributes}
                for k, v in attributes.items()
            }
        return attributes

    def query_assertion(self, path):
        """
        Query SAML assertion for specific data by element path.

        Args:
            path (basestring): path to element within assertion

        Returns:
            (`list` of `lxml.etree.Element`) requested nodes
        """
        return self._query_assertion(path)

    def query(self, path):
        """
        Query SAML response document for specific data by element path.

        Args:
            path (basestring): path to element

        Returns:
            (`list` of `lxml.etree.Element`) requested nodes
        """
        return self._query(path)


class CustomXMLParser(OneLogin_Saml2_XML):
    """
    Wrapper for OneLogin XML parser to allow for alternative parsing methods.
    """

    @classmethod
    def parse(cls, xml, relaxed=False):
        """
        Parse XML document with option of using a relaxed parser, which will attempt
        to recover syntactically-flawed XML.

        Args:
            xml (`str` or `bytes` or `xml.dom.minidom.Document` or `etree.Element`): the string to parse
            relaxed (bool): True attempts to recover flawed XML. Default: False

        Returns:
            (OneLogin_Saml2_XML._element_class) the root node of the XML document

        Raises:
            (SamlParsingError) if the document cannot be successfully parsed
        """
        if not relaxed:
            cls.set_parser_to_strict()
        else:
            cls.set_parser_to_relaxed()

        try:
            document = cls.to_etree(xml)
        except etree.XMLSyntaxError:
            # Usually thrown with strict parser and syntax error
            raise SamlParsingError(
                "Could not parse the XML data", "relaxed" if relaxed else "strict"
            )
        except AttributeError as e:
            if e.args[0].endswith("'getroottree'"):
                # When using the relaxed parser, if the cython function which parses
                # the XML cannot recover the XML, it will simply return None for the document.
                # Then, when the encapsulating function (`lxml.fromstring()`) subsequently tries
                # to access the `getroottree()` class method, expecting an `lxml.etree.Element` object,
                # no such method is found and an AttributeError is thrown.
                raise SamlParsingError(
                    "Could not parse the XML data", "relaxed" if relaxed else "strict"
                )
            else:
                raise e

        return document

    @classmethod
    def to_etree(cls, xml):
        """
        Parses an XML document or fragment from a string.

        Args:
            xml (`str` or `bytes` or `xml.dom.minidom.Document` or `etree.Element`): the string to parse

        Returns:
            (OneLogin_Saml2_XML._element_class) the root node
        """
        # This is nearly verbatim the method from the super method,
        # except this method calls other methods from this class using cls.
        # The super class explicitly calls these methods by explicitly using
        # its name instead of using cls, which is why modifying the parser
        # and parsing with the inherited method doesn't work.

        if isinstance(xml, cls._element_class):
            return xml
        if isinstance(xml, cls._bytes_class):
            return cls._parse_etree(xml, forbid_dtd=True)
        if isinstance(xml, cls._text_class):
            return cls._parse_etree(compat.to_bytes(xml), forbid_dtd=True)

    @classmethod
    def set_parser_to_relaxed(cls):
        """
        Creates a XML parser which attempts to recover syntactically-flawed XML.

        Returns:
            None
        """
        # Creates an `etree.XMLParser` object, equivalent to the default parser used
        # by the parser `lxml.fromstring()` (see `lxml.GlobalParserTLS.createDefaultParser()`),
        # except enabling the `recover=True` attribute.

        relaxed_xml_parser = etree.XMLParser(recover=True, resolve_entities=False)
        lookup = etree.ElementDefaultClassLookup(element=RestrictedElement)
        relaxed_xml_parser.set_element_class_lookup(lookup)
        # Inject parser
        cls._parse_etree = partial(super()._parse_etree, parser=relaxed_xml_parser)

    @classmethod
    def set_parser_to_strict(cls):
        """
        Set parser to default strict parser (does not attempt to recover flawed XML).

        Returns:
            None
        """
        cls._parse_etree = super()._parse_etree

import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetDomain, Username, TargetHostname, OperatingSystem, OSTYPE_WINDOWS, ScanPresent, \
    WindowsDomain
from shadycompass.facts.ldap_scanner.ldapsearch import LdapSearchReader
from shadycompass.rules.ldap_scanner.ldapsearch import LdapSearchRules


class LdapSearchReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = LdapSearchReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/ldapsearch/ldapsearch-base-shadycompass.test-10.129.229.189.txt')
        self.assertIn(ScanPresent(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name,
                                  hostname='DC01.shadycompass.test', addr='10.129.229.189'), facts)
        self.assertIn(TargetDomain(domain='shadycompass.test'), facts)
        self.assertIn(WindowsDomain(netbios_domain_name='shadycompass', dns_domain_name='shadycompass.test'), facts)
        self.assertIn(Username(username='Administrator', domain='shadycompass'), facts)
        self.assertIn(Username(username='Guest', domain='shadycompass'), facts)
        self.assertIn(Username(username='krbtgt', domain='shadycompass'), facts)
        self.assertIn(Username(username='Zhong', domain='shadycompass'), facts)
        self.assertIn(Username(username='Cheng', domain='shadycompass'), facts)
        self.assertIn(Username(username='Ryan', domain='shadycompass'), facts)
        self.assertIn(Username(username='Raven', domain='shadycompass'), facts)
        self.assertIn(Username(username='JinWoo', domain='shadycompass'), facts)
        self.assertIn(Username(username='ChinHae', domain='shadycompass'), facts)
        self.assertIn(Username(username='Operator', domain='shadycompass'), facts)
        self.assertIn(TargetHostname(hostname='DC01.shadycompass.test'), facts)
        self.assertIn(OperatingSystem(hostname='DC01.shadycompass.test', os_type=OSTYPE_WINDOWS,
                                      version='Windows Server 2019 Standard 10.0 (17763)'), facts)
        self.assertEqual(15, len(facts))

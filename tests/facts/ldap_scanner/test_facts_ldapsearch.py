import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetDomain, Username, TargetHostname, OperatingSystem, OSTYPE_WINDOWS, ScanPresent, \
    WindowsDomain, WindowsDomainController
from shadycompass.facts.ldap_scanner.ldapsearch import LdapSearchReader
from shadycompass.rules.ldap_scanner.ldapsearch import LdapSearchRules
from tests.tests import assertFactIn


class LdapSearchReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = LdapSearchReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/ldapsearch/ldapsearch-base-shadycompass.test-10.129.229.189.txt')
        assertFactIn(ScanPresent(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name,
                                 hostname='dc01.shadycompass.test', addr='10.129.229.189'), facts)
        assertFactIn(TargetDomain(domain='shadycompass.test'), facts)
        assertFactIn(WindowsDomain(netbios_domain_name='shadycompass', dns_domain_name='shadycompass.test'), facts)
        assertFactIn(Username(username='Administrator', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Guest', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='krbtgt', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Zhong', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Cheng', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Ryan', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Raven', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='JinWoo', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='ChinHae', domain='SHADYCOMPASS'), facts)
        assertFactIn(Username(username='Operator', domain='SHADYCOMPASS'), facts)
        assertFactIn(TargetHostname(hostname='dc01.shadycompass.test'), facts)
        assertFactIn(WindowsDomainController(
            hostname='dc01.shadycompass.test',
            netbios_domain_name='SHADYCOMPASS',
            netbios_computer_name='DC01',
            dns_domain_name='shadycompass.test',
        ), facts)
        assertFactIn(OperatingSystem(hostname='dc01.shadycompass.test', os_type=OSTYPE_WINDOWS,
                                      version='Windows Server 2019 Standard 10.0 (17763)'), facts)
        self.assertEqual(16, len(facts))

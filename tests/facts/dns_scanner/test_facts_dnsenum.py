import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, ScanPresent, \
    HostnameIPv4Resolution
from shadycompass.facts.dns_scanner.dnsenum import DnsEnumReader
from shadycompass.rules.dns_scanner.dnsenum import DnsEnumRules


class DnsEnumReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = DnsEnumReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/dnsenum/dnsenum-subdomains-shadycompass.test.xml')
        self.assertIn(ScanPresent(category=ToolCategory.dns_scanner, name=DnsEnumRules.dnsenum_tool_name,
                                  hostname='shadycompass.test', port=53), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetIPv4Address(addr='192.168.5.1'), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='192.168.5.1', implied=False), facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='dc.shadycompass.test', addr='10.129.229.189', implied=False),
                      facts)
        self.assertIn(TargetHostname(hostname='gc._msdcs.shadycompass.test'), facts)
        self.assertIn(
            HostnameIPv4Resolution(hostname='gc._msdcs.shadycompass.test', addr='10.129.229.189', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='gc._msdcs.shadycompass.test', addr='192.168.5.1', implied=False),
                      facts)
        self.assertIn(TargetHostname(hostname='domaindnszones.shadycompass.test'), facts)
        self.assertIn(
            HostnameIPv4Resolution(hostname='domaindnszones.shadycompass.test', addr='10.129.229.189', implied=False),
            facts)
        self.assertIn(
            HostnameIPv4Resolution(hostname='domaindnszones.shadycompass.test', addr='192.168.5.1', implied=False),
            facts)
        self.assertIn(TargetHostname(hostname='forestdnszones.shadycompass.test'), facts)
        self.assertIn(
            HostnameIPv4Resolution(hostname='forestdnszones.shadycompass.test', addr='10.129.229.189', implied=False),
            facts)
        self.assertIn(
            HostnameIPv4Resolution(hostname='forestdnszones.shadycompass.test', addr='192.168.5.1', implied=False),
            facts)
        self.assertEqual(17, len(facts))

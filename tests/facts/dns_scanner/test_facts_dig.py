import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, ScanPresent, \
    HostnameIPv4Resolution, TargetIPv6Address, HostnameIPv6Resolution
from shadycompass.facts.dns_scanner.dig import DigReader
from shadycompass.rules.dns_scanner.dig import DigRules


class DigReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = DigReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/dig/dig-any-shadycompass.test.txt')
        self.assertIn(ScanPresent(category=ToolCategory.dns_scanner, name=DigRules.dig_tool_name,
                                  addr='10.129.229.189', hostname='shadycompass.test', port=53), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetIPv4Address(addr='192.168.5.1'), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='192.168.5.1', implied=False), facts)
        self.assertIn(TargetIPv6Address(addr='dead:beef::8a13:3848:1b43:e9a'), facts)
        self.assertIn(TargetIPv6Address(addr='dead:beef::242'), facts)
        self.assertIn(TargetIPv6Address(addr='dead:beef::213'), facts)
        self.assertIn(TargetIPv6Address(addr='dead:beef::de00:630b:3893:7608'), facts)
        self.assertIn(
            HostnameIPv6Resolution(hostname='shadycompass.test', addr='dead:beef::8a13:3848:1b43:e9a', implied=False),
            facts)
        self.assertIn(HostnameIPv6Resolution(hostname='shadycompass.test', addr='dead:beef::242', implied=False), facts)
        self.assertIn(HostnameIPv6Resolution(hostname='shadycompass.test', addr='dead:beef::213', implied=False), facts)
        self.assertIn(
            HostnameIPv6Resolution(hostname='shadycompass.test', addr='dead:beef::de00:630b:3893:7608', implied=False),
            facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='dc.shadycompass.test', addr='10.129.229.189', implied=False),
                      facts)
        self.assertIn(HostnameIPv6Resolution(hostname='dc.shadycompass.test', addr='dead:beef::de00:630b:3893:7608',
                                             implied=False), facts)
        self.assertEqual(17, len(facts))

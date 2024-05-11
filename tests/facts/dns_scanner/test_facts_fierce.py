import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, ScanPresent, \
    HostnameIPv4Resolution
from shadycompass.facts.dns_scanner.fierce import FierceReader
from shadycompass.rules.dns_scanner.fierce import FierceRules


class FierceReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = FierceReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/fierce/fierce-shadycompass.test.txt')
        self.assertEqual(4, len(facts))
        self.assertIn(ScanPresent(category=ToolCategory.dns_scanner, name=FierceRules.fierce_tool_name,
                                  hostname='dc.shadycompass.test', addr='10.129.229.189', port=53), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='dc.shadycompass.test', addr='10.129.229.189', implied=False),
                      facts)

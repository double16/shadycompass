import unittest

from shadycompass import Username, TargetDomain, TargetHostname
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanPresent, UsernamePassword
from shadycompass.facts.kerberos.kerbrute import KerbruteReader
from shadycompass.rules.kerberos.kerbrute import KerbruteRules


class KerbruteReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = KerbruteReader()

    def test_userenum(self):
        facts = self.reader.read_facts('tests/fixtures/kerbrute/kerbrute-userenum-shadycompass.test.txt')
        self.assertIn(Username(username='tom', domain='shadycompass.test'), facts)
        self.assertIn(Username(username='jerry', domain='shadycompass.test'), facts)
        self.assertIn(Username(username='Administrator', domain='shadycompass.test'), facts)
        self.assertIn(TargetDomain(domain='shadycompass.test'), facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        self.assertIn(ScanPresent(category=ToolCategory.asrep_roaster, name=KerbruteRules.kerbrute_tool_name,
                                  hostname='dc.shadycompass.test'), facts)
        self.assertEqual(6, len(facts))

    def test_passwordspray(self):
        facts = self.reader.read_facts('tests/fixtures/kerbrute/kerbrute-passwordspray-shadycompass.test.txt')
        self.assertIn(UsernamePassword(username='tom', password='catzrule', domain='shadycompass.test'), facts)
        self.assertIn(UsernamePassword(username='jerry', password='tomdrulz', domain='shadycompass.test'), facts)
        self.assertIn(TargetDomain(domain='shadycompass.test'), facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        # self.assertIn(ScanPresent(category=ToolCategory.password_scanner, name=KerbruteRules.kerbrute_tool_name, hostname='dc.shadycompass.test'), facts)
        self.assertEqual(4, len(facts))

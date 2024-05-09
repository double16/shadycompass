import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, Username, ScanPresent, EmailAddress
from shadycompass.facts.smtp_scanner.smtp_user_enum import SmtpUserEnumReader
from shadycompass.rules.smtp_scanner.smtp_user_enum import SmtpUserEnumRules


class SmtpUserEnumReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = SmtpUserEnumReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/smtp_user_enum/smtp_user_enum-10.0.0.1-25.txt')
        self.assertEqual(23, len(facts))
        self.assertIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  addr='10.0.0.1', port=25), facts)
        self.assertIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  addr='10.0.0.2', port=25), facts)
        self.assertIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  hostname='shadycompass.test', port=25), facts)
        self.assertIn(TargetIPv4Address(addr='10.0.0.1'), facts)
        self.assertIn(TargetIPv4Address(addr='10.0.0.2'), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(Username(username='root', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='bin', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='daemon', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='lp', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='adm', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='uucp', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='postmaster', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='nobody', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='ftp', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='root', addr='10.0.0.2'), facts)
        self.assertIn(Username(username='bin', addr='10.0.0.2'), facts)
        self.assertIn(Username(username='root', hostname='shadycompass.test'), facts)
        self.assertIn(Username(username='bin', hostname='shadycompass.test'), facts)
        self.assertIn(Username(username='root@shadycompass.test', addr='10.0.0.1'), facts)
        self.assertIn(Username(username='bin@shadycompass.test', addr='10.0.0.1'), facts)
        self.assertIn(EmailAddress(email='root@shadycompass.test'), facts)
        self.assertIn(EmailAddress(email='bin@shadycompass.test'), facts)

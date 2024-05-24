import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, Username, ScanPresent, EmailAddress
from shadycompass.facts.smtp_scanner.smtp_user_enum import SmtpUserEnumReader
from shadycompass.rules.smtp_scanner.smtp_user_enum import SmtpUserEnumRules
from tests.tests import assertFactIn, facts_str


class SmtpUserEnumReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = SmtpUserEnumReader()

    def test_facts_emails(self):
        facts = self.reader.read_facts('tests/fixtures/smtp_user_enum/smtp_user_enum-emails-10.0.0.1-25.txt')
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  addr='10.0.0.1', port=25), facts)
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  addr='10.0.0.2', port=25), facts)
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                  hostname='shadycompass.test', port=25), facts)
        assertFactIn(TargetIPv4Address(addr='10.0.0.1'), facts)
        assertFactIn(TargetIPv4Address(addr='10.0.0.2'), facts)
        assertFactIn(TargetHostname(hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='root', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='bin', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='daemon', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='lp', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='adm', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='uucp', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='postmaster', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='nobody', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='ftp', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='root', addr='10.0.0.2'), facts)
        assertFactIn(Username(username='bin', addr='10.0.0.2'), facts)
        assertFactIn(Username(username='root', hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='bin', hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='root@shadycompass.test', addr='10.0.0.1'), facts)
        assertFactIn(Username(username='bin@shadycompass.test', addr='10.0.0.1'), facts)
        assertFactIn(EmailAddress(email='root@shadycompass.test'), facts)
        assertFactIn(EmailAddress(email='bin@shadycompass.test'), facts)
        self.assertEqual(23, len(facts), facts_str(facts))

    def test_facts_users(self):
        facts = self.reader.read_facts('tests/fixtures/smtp_user_enum/smtp_user_enum-users-10.0.0.1-25.txt')
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name,
                                 hostname='shadycompass.test', port=25), facts)
        assertFactIn(TargetHostname(hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='root', hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='alex', hostname='shadycompass.test'), facts)
        assertFactIn(Username(username='mail', hostname='shadycompass.test'), facts)
        assertFactIn(EmailAddress(email='root@shadycompass.test'), facts)
        assertFactIn(EmailAddress(email='alex@shadycompass.test'), facts)
        assertFactIn(EmailAddress(email='mail@shadycompass.test'), facts)
        self.assertEqual(8, len(facts), facts_str(facts))

import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import VirtualHostname, ScanPresent
from shadycompass.facts.http_buster.gobuster import GobusterReader
from tests.tests import assertFactIn, facts_str


class GobusterVirtualHostReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = GobusterReader()

    def test_facts_443(self):
        facts = self.reader.read_facts(
            'tests/fixtures/gobuster/virtualhost_scanner/gobuster-vhost-443-shadycompass.test.txt')
        assertFactIn(VirtualHostname(
            hostname='ns3.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(
            hostname='blog.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(
            hostname='ftp.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(
            ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', port=443, hostname='shadycompass.test'), facts)
        self.assertEqual(4, len(facts), facts_str(facts))

    def test_facts_80(self):
        facts = self.reader.read_facts(
            'tests/fixtures/gobuster/virtualhost_scanner/gobuster-vhost-80-shadycompass.test.txt')
        assertFactIn(VirtualHostname(
            hostname='auth.shadycompass.test', domain='shadycompass.test', port=80, secure=False), facts)
        assertFactIn(VirtualHostname(
            hostname='report.shadycompass.test', domain='shadycompass.test', port=80, secure=False), facts)
        assertFactIn(VirtualHostname(
            hostname='dashboard.shadycompass.test', domain='shadycompass.test', port=80, secure=False), facts)
        assertFactIn(
            ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', port=80, hostname='shadycompass.test'), facts)
        self.assertEqual(4, len(facts), facts_str(facts))

    def test_facts_302_all(self):
        facts = self.reader.read_facts(
            'tests/fixtures/gobuster/virtualhost_scanner/gobuster-vhost-80-shadycompass.test-redirall.txt')
        assertFactIn(VirtualHostname(
            hostname='lms.shadycompass.test', domain='shadycompass.test', port=80, secure=False), facts)
        assertFactIn(
            ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', port=80, hostname='shadycompass.test'), facts)
        self.assertEqual(2, len(facts), facts_str(facts))

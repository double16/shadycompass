import unittest

from shadycompass.facts import VirtualHostname
from shadycompass.facts.http_buster.wfuzz import WfuzzReader
from tests.tests import assertFactIn, facts_str


class WfuzzVirtualHostReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = WfuzzReader()

    def _assert_facts(self, facts: list):
        assertFactIn(VirtualHostname(
            hostname='ns3.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(
            hostname='blog.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(
            hostname='ftp.shadycompass.test', domain='shadycompass.test', port=443, secure=True), facts)

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/virtualhost_scanner/wfuzz-vhost-10.129.157.138-443.json')
        self._assert_facts(facts)
        self.assertEqual(7, len(facts), facts_str(facts))

    def test_read_txt(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/virtualhost_scanner/wfuzz-vhost-10.129.157.138-443.txt')
        self._assert_facts(facts)
        self.assertEqual(4, len(facts), facts_str(facts))

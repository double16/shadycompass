import unittest

from shadycompass.facts import HttpUrl, VirtualHostname
from shadycompass.facts.http_buster.wfuzz import WfuzzReader
from tests.tests import assertFactIn, facts_str


class WfuzzReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = WfuzzReader()

    def _assert_facts(self, facts: list):
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/index.php'),
                     facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/favicon.ico'),
                     facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/.'), facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/Index.php'),
                     facts)

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/http_buster/wfuzz.json')
        self._assert_facts(facts)
        self.assertEqual(6, len(facts), facts_str(facts))

    def test_read_txt(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/http_buster/wfuzz.txt')
        self._assert_facts(facts)
        self.assertEqual(5, len(facts), facts_str(facts))

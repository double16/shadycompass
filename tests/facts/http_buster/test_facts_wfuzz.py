import unittest

from shadycompass.facts import HttpUrl, TargetHostname
from shadycompass.facts.http_buster.wfuzz import WfuzzReader


class WfuzzReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = WfuzzReader()

    def _assert_facts(self, facts: list):
        self.assertEqual(5, len(facts))
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/index.php'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/favicon.ico'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/.'), facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/Index.php'),
                      facts)

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/wfuzz.json')
        self._assert_facts(facts)

    def test_read_txt(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/wfuzz.txt')
        self._assert_facts(facts)

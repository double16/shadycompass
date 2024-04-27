import unittest

from shadycompass.facts.http_buster.wfuzz import WfuzzReader
from shadycompass.facts import HttpUrl


class WfuzzReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = WfuzzReader()

    def _assert_facts(self, facts: list):
        self.assertEqual(4, len(facts))
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb:443/index.php'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb:443/favicon.ico'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb:443/.'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb:443/Index.php'), facts)

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/wfuzz.json')
        self._assert_facts(facts)

    def test_read_txt(self):
        facts = self.reader.read_facts('tests/fixtures/wfuzz/wfuzz.txt')
        self.assertEqual(4, len(facts))
        self._assert_facts(facts)

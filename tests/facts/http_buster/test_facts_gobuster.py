import unittest

from shadycompass.facts.http_buster.gobuster import GobusterReader
from shadycompass.facts import HttpUrl


class GobusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = GobusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/gobuster/gobuster-8080-hospital.htb-dirs.txt')
        self.assertEqual(8, len(facts))
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/images/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/js/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/css/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/uploads/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/fonts/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/icons/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/vendor/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='hospital.htb', url='http://hospital.htb:8080/server-status/'), facts)

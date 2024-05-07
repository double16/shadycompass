import unittest

from shadycompass.facts import HttpUrl, TargetHostname
from shadycompass.facts.http_buster.gobuster import GobusterReader


class GobusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = GobusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/gobuster/gobuster-8080-shadycompass.test-dirs.txt')
        self.assertEqual(9, len(facts))
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/images/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/js/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/css/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/uploads/'),
                      facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/fonts/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/icons/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/vendor/'), facts)
        self.assertIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/server-status/'),
                      facts)

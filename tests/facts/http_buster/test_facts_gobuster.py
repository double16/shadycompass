import unittest

from shadycompass.facts import HttpUrl, VirtualHostname
from shadycompass.facts.http_buster.gobuster import GobusterReader
from tests.tests import assertFactIn


class GobusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = GobusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/gobuster/http_buster/gobuster-8080-shadycompass.test-dirs.txt')
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/images/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/js/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/css/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/uploads/'),
                      facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/fonts/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/icons/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/vendor/'), facts)
        assertFactIn(HttpUrl(port=8080, vhost='shadycompass.test', url='http://shadycompass.test:8080/server-status/'),
                      facts)
        self.assertEqual(9, len(facts))

import unittest

from shadycompass.facts import HttpUrl, VirtualHostname
from shadycompass.facts.http_buster.dirb import DirbReader
from tests.tests import facts_str, assertFactIn


class DirbReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = DirbReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/dirb/dirb-443-dirs.txt')
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/examples'), facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/favicon.ico'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/index.php'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/aux'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com1'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com2'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com3'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/con'),
                      facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/index.php'),
            facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/lpt1'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/lpt2'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/nul'),
                      facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/prn'),
                      facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/aux'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com1'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com2'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com3'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/con'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/lpt1'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/lpt2'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/nul'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/prn'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/aux'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com1'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com2'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com3'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/con'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/lpt1'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/lpt2'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/nul'),
            facts)
        self.assertEqual(31, len(facts), facts_str(facts))

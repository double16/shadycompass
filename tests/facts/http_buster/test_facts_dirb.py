import unittest

from shadycompass.facts import HttpUrl, TargetHostname
from shadycompass.facts.http_buster.dirb import DirbReader


class DirbReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = DirbReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/dirb/dirb-443-dirs.txt')
        self.assertEqual(31, len(facts))
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/examples'), facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/favicon.ico'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/index.php'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/aux'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com1'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com2'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/com3'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/con'),
                      facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/index.php'),
            facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/lpt1'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/lpt2'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/nul'),
                      facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/prn'),
                      facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/aux'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com1'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com2'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/com3'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/con'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/lpt1'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/lpt2'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/nul'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/images/prn'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/aux'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com1'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com2'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/com3'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/con'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/lpt1'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/lpt2'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/installer/Images/nul'),
            facts)

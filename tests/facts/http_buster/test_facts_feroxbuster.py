import unittest

from shadycompass.facts import HttpUrl, TargetHostname
from shadycompass.facts.http_buster.feroxbuster import FeroxbusterReader


class FeroxbusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = FeroxbusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/feroxbuster/ferox-443-dirs.txt')
        self.assertEqual(640, len(facts))
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/program/js/jstz.min.js'), facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/skins/elastic/images/favicon.ico'), facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/skins/elastic/images/logo.svg'),
            facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/skins/elastic/watermark.html'),
            facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/plugins/jqueryui/themes/elastic/jquery-ui.min.css'), facts)
        self.assertIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/program/js/jquery.min.js'),
            facts)
        self.assertIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/skins/elastic/deps/bootstrap.bundle.min.js'), facts)

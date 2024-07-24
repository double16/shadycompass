import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import HttpUrl, VirtualHostname, ScanPresent
from shadycompass.facts.http_buster.feroxbuster import FeroxbusterReader
from tests.tests import facts_str, assertFactIn


class FeroxbusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = FeroxbusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/feroxbuster/ferox-443-dirs.txt')
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/program/js/jstz.min.js'), facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/skins/elastic/images/favicon.ico'), facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/skins/elastic/images/logo.svg'),
            facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/skins/elastic/watermark.html'),
            facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/plugins/jqueryui/themes/elastic/jquery-ui.min.css'), facts)
        assertFactIn(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test/program/js/jquery.min.js'),
            facts)
        assertFactIn(HttpUrl(port=443, vhost='shadycompass.test',
                              url='https://shadycompass.test/skins/elastic/deps/bootstrap.bundle.min.js'), facts)
        assertFactIn(ScanPresent(category=ToolCategory.http_buster, name='feroxbuster', secure=True, port=443,
                                 hostname='shadycompass.test', url='https://shadycompass.test:443'), facts)
        self.assertEqual(641, len(facts), facts_str(facts))

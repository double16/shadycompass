import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import VirtualHostname, ScanPresent
from shadycompass.facts.http_spider.gospider import GospiderReader
from tests.tests import assertFactIn, assertFactNotIn


class GospiderReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = GospiderReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/gospider/shadycompass_test')
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='gospider', secure=True, port=443,
                                 hostname='shadycompass.test', url='https://shadycompass.test:443'), facts)
        assertFactNotIn(ScanPresent(category=ToolCategory.http_spider, name='gospider',
                                    hostname='store.shadycompass.test'), facts)
        assertFactNotIn(ScanPresent(category=ToolCategory.http_spider, name='gospider',
                                    hostname='ir.shadycompass.test'), facts)
        assertFactNotIn(ScanPresent(category=ToolCategory.http_spider, name='gospider',
                                    hostname='footer-ir.shadycompass.test'), facts)
        assertFactNotIn(ScanPresent(category=ToolCategory.http_spider, name='gospider',
                                    hostname='footer-store.shadycompass.test'), facts)
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)
        assertFactIn(VirtualHostname(hostname='store.shadycompass.test'), facts)
        assertFactIn(VirtualHostname(hostname='ir.shadycompass.test'), facts)
        assertFactIn(VirtualHostname(hostname='footer-ir.shadycompass.test'), facts)
        assertFactIn(VirtualHostname(hostname='footer-store.shadycompass.test'), facts)

    def test_facts_not_gospider_output(self):
        facts = self.reader.read_facts('tests/fixtures/shadycompass.ini')
        self.assertEqual(0, len(facts))

import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import VirtualHostname, ScanPresent
from shadycompass.facts.http_spider.katana import KatanaReader
from tests.tests import assertFactIn


class KatanaReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = KatanaReader()

    def test_facts_active(self):
        facts = self.reader.read_facts('tests/fixtures/katana/katana-443-shadycompass.test.json')
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=True, port=443,
                                 hostname='shadycompass.test', url='https://shadycompass.test:443'), facts)
        assertFactIn(VirtualHostname(hostname='shadycompass.test'), facts)

    def test_facts_passive(self):
        facts = self.reader.read_facts('tests/fixtures/katana/katana-443-shadycompass.test-passive.json')
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=True, port=443,
                                 hostname='shadycompass.test', url='https://shadycompass.test:443'), facts)
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=False, port=80,
                                 hostname='shadycompass.test', url='http://shadycompass.test:80'), facts)
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=True, port=443,
                                 hostname='www.shadycompass.test', url='https://www.shadycompass.test:443'), facts)
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=False, port=80,
                                 hostname='www.shadycompass.test', url='http://www.shadycompass.test:80'), facts)
        assertFactIn(ScanPresent(category=ToolCategory.http_spider, name='katana', secure=False, port=80,
                                 hostname='www.vpn.shadycompass.test', url='http://www.vpn.shadycompass.test:80'),
                     facts)
        assertFactIn(VirtualHostname(hostname='shadycompass.test', port=80, secure=False), facts)
        assertFactIn(VirtualHostname(hostname='shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(hostname='www.shadycompass.test', port=80, secure=False), facts)
        assertFactIn(VirtualHostname(hostname='www.shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(hostname='ir.shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(hostname='www.vpn.shadycompass.test', port=80, secure=False), facts)
        assertFactIn(VirtualHostname(hostname='www.vpn.shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(hostname='click.e.shadycompass.test', port=443, secure=True), facts)
        assertFactIn(VirtualHostname(hostname='techinfo.shadycompass.test', port=443, secure=True), facts)

    def test_facts_not_katana_output(self):
        facts = self.reader.read_facts('tests/fixtures/shadycompass.ini')
        self.assertEqual(0, len(facts))

import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetIPv4Address, HttpService, Product, \
    ScanPresent, Username
from shadycompass.facts.wordpress_scanner.wpscan import WpscanReader
from tests.tests import assertFactIn, facts_str


class WpscanReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = WpscanReader()

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/wpscan/wpscan.json')
        assertFactIn(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.129.229.189', port=80),
            facts)
        assertFactIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        assertFactIn(HttpService(addr='10.129.229.189', port=80, secure=False), facts)
        assertFactIn(Product(product='wordpress', version='5.4', addr='10.129.229.189', port=80, secure=False), facts)
        assertFactIn(Username(username='user1', addr='10.129.229.189'), facts)
        self.assertEqual(5, len(facts), facts_str(facts))

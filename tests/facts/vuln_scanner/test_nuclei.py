import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import HostnameIPv4Resolution, TargetIPv4Address, TargetHostname, HttpService, Product, \
    OSTYPE_WINDOWS, MsmqService, SshService, RdpService, ScanPresent
from shadycompass.facts.vuln_scanner.nuclei import NucleiJsonFactReader
from shadycompass.rules.vuln_scanner.nuclei import NucleiRules


class NucleiJsonFactReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = NucleiJsonFactReader()

    def test_read_json(self):
        facts = self.reader.read_facts('tests/fixtures/nuclei/nuclei-shadycompass.test.json')
        self.assertEqual(13, len(facts))
        self.assertIn(ScanPresent(category=ToolCategory.vuln_scanner, name=NucleiRules.nuclei_tool_name, addr='10.129.229.189'), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=True), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=443, secure=True), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=80, secure=False), facts)
        self.assertIn(Product(product='apache', version='2.4.56', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="shadycompass.test"), facts)
        self.assertIn(Product(product='openssl', version='1.1.1t', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="shadycompass.test"), facts)
        self.assertIn(Product(product='php', version='8.0.28', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="shadycompass.test"), facts)
        self.assertIn(SshService(addr='10.129.229.189', port=22), facts)
        self.assertIn(MsmqService(addr='10.129.229.189', port=1801), facts)
        self.assertIn(RdpService(addr='10.129.229.189', port=3389), facts)

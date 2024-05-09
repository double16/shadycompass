import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import TargetHostname, TargetIPv4Address, ScanPresent, \
    HostnameIPv4Resolution, TargetIPv6Address, HostnameIPv6Resolution, Kerberos5SecUdpService, LdapService, \
    Kerberos5SecTcpService
from shadycompass.facts.dns_scanner.dnsrecon import DnsReconReader
from shadycompass.rules.dns_scanner.dnsrecon import DnsReconRules


class DnsReconReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = DnsReconReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/dnsrecon/dnsrecon-shadycompass.test.txt')
        self.assertIn(ScanPresent(category=ToolCategory.dns_scanner, name=DnsReconRules.dnsrecon_tool_name,
                                  hostname='shadycompass.test', port=53), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetIPv4Address(addr='192.168.5.1'), facts)
        self.assertIn(TargetIPv6Address(addr='dead:beef::de00:630b:3893:7608'), facts)
        self.assertIn(TargetHostname(hostname='dc.shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='dc.shadycompass.test', addr='10.129.229.189', implied=False),
                      facts)
        self.assertIn(HostnameIPv4Resolution(hostname='dc.shadycompass.test', addr='192.168.5.1', implied=False), facts)
        self.assertIn(HostnameIPv6Resolution(hostname='dc.shadycompass.test', addr='dead:beef::de00:630b:3893:7608',
                                             implied=False), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='192.168.5.1', implied=False), facts)
        self.assertIn(
            HostnameIPv6Resolution(hostname='shadycompass.test', addr='dead:beef::de00:630b:3893:7608', implied=False),
            facts)

        self.assertIn(Kerberos5SecUdpService(addr='10.129.229.189', port=88), facts)
        self.assertIn(Kerberos5SecUdpService(addr='192.168.5.1', port=88), facts)
        self.assertIn(Kerberos5SecUdpService(addr='dead:beef::de00:630b:3893:7608', port=88), facts)
        self.assertIn(Kerberos5SecTcpService(addr='10.129.229.189', port=88), facts)
        self.assertIn(Kerberos5SecTcpService(addr='192.168.5.1', port=88), facts)
        self.assertIn(Kerberos5SecTcpService(addr='dead:beef::de00:630b:3893:7608', port=88), facts)
        self.assertIn(LdapService(addr='10.129.229.189', port=3268, secure=True), facts)
        self.assertIn(LdapService(addr='192.168.5.1', port=3268, secure=True), facts)
        self.assertIn(LdapService(addr='dead:beef::de00:630b:3893:7608', port=3268, secure=True), facts)
        self.assertIn(LdapService(addr='10.129.229.189', port=389, secure=False), facts)
        self.assertIn(LdapService(addr='192.168.5.1', port=389, secure=False), facts)
        self.assertIn(LdapService(addr='dead:beef::de00:630b:3893:7608', port=389, secure=False), facts)
        self.assertIn(Kerberos5SecUdpService(addr='10.129.229.189', port=464), facts)
        self.assertIn(Kerberos5SecUdpService(addr='192.168.5.1', port=464), facts)
        self.assertIn(Kerberos5SecUdpService(addr='dead:beef::de00:630b:3893:7608', port=464), facts)
        self.assertIn(Kerberos5SecTcpService(addr='10.129.229.189', port=464), facts)
        self.assertIn(Kerberos5SecTcpService(addr='192.168.5.1', port=464), facts)
        self.assertIn(Kerberos5SecTcpService(addr='dead:beef::de00:630b:3893:7608', port=464), facts)
        self.assertEqual(45, len(facts))

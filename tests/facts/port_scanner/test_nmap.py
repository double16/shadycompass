import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import HostnameIPv4Resolution, TargetIPv4Address, TargetHostname, TcpIpService, \
    DomainTcpIpService, HttpService, WinRMService, Kerberos5SecTcpService, MicrosoftRpcService, NetbiosSessionService, \
    LdapService, SmbService, RdpService, MsmqService, Product, OSTYPE_WINDOWS, DotNetMessageFramingService, \
    MicrosoftRpcHttpService, SshService, ScanPresent, OperatingSystem
from shadycompass.facts.port_scanner.nmap import NmapXmlFactReader
from shadycompass.rules.port_scanner.nmap import NmapRules


class NmapXmlFactReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = NmapXmlFactReader()

    def test_read_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/open-ports.xml')
        self.assertEqual(80, len(facts))
        self.assertIn(ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr='10.129.229.189'), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetHostname(hostname='shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=True), facts)
        self.assertIn(SshService(addr='10.129.229.189', port=22), facts)
        self.assertIn(DomainTcpIpService(addr='10.129.229.189', port=53), facts)
        self.assertIn(Kerberos5SecTcpService(addr='10.129.229.189', port=88), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=135), facts)
        self.assertIn(NetbiosSessionService(addr='10.129.229.189', port=139), facts)
        self.assertIn(LdapService(addr='10.129.229.189', port=389, secure=False), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=443, secure=True), facts)
        self.assertIn(SmbService(addr='10.129.229.189', port=445), facts)
        self.assertIn(Kerberos5SecTcpService(addr='10.129.229.189', port=464), facts)
        self.assertIn(MicrosoftRpcHttpService(addr='10.129.229.189', port=593), facts)
        self.assertIn(LdapService(addr='10.129.229.189', port=636, secure=True), facts)
        self.assertIn(MsmqService(addr='10.129.229.189', port=1801), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=2103), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=2105), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=2107), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=2179), facts)
        self.assertIn(LdapService(addr='10.129.229.189', port=3268, secure=False), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=3269), facts)
        self.assertIn(RdpService(addr='10.129.229.189', port=3389), facts)
        self.assertIn(WinRMService(addr='10.129.229.189', port=5985, secure=False), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=6404), facts)
        self.assertIn(MicrosoftRpcHttpService(addr='10.129.229.189', port=6406), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=6407), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=6409), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=6616), facts)
        self.assertIn(MicrosoftRpcService(addr='10.129.229.189', port=6637), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=8080, secure=False), facts)
        self.assertIn(DotNetMessageFramingService(addr='10.129.229.189', port=9389), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=True), facts)
        self.assertIn(Product(product='apache httpd', version='2.4.56', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="www.example.com"), facts)
        self.assertIn(Product(product='openssl', version='1.1.1t', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="www.example.com"), facts)
        self.assertIn(Product(product='php', version='8.0.28', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="www.example.com"), facts)
        self.assertIn(Product(addr='10.129.229.189', product='openssh', os_type='linux', port=22,
                              version='9.0p1 ubuntu 1ubuntu8.5'), facts)
        self.assertIn(Product(addr='10.129.229.189', product='simple dns plus', os_type='windows', port=53), facts)
        self.assertIn(Product(addr='10.129.229.189', product='microsoft windows kerberos', os_type='windows', port=88),
                      facts)
        self.assertIn(TargetHostname(hostname='webmail.shadycompass.test'), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='webmail.shadycompass.test', addr='10.129.229.189', implied=True),
                      facts)
        self.assertIn(OperatingSystem(addr='10.129.229.189', port=593, os_type='windows'), facts)
        self.assertIn(OperatingSystem(addr='10.129.229.189', port=22, os_type='linux'), facts)

    def test_ignore_not_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/open-ports.txt')
        self.assertEqual(0, len(facts))

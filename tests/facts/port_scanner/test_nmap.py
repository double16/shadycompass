import unittest

from shadycompass.config import ToolCategory
from shadycompass.facts import HostnameIPv4Resolution, TargetIPv4Address, TargetHostname, \
    DomainTcpIpService, HttpService, WinRMService, Kerberos5SecTcpService, MicrosoftRpcService, NetbiosSessionService, \
    LdapService, SmbService, RdpService, MsmqService, Product, OSTYPE_WINDOWS, DotNetMessageFramingService, \
    MicrosoftRpcHttpService, SshService, ScanPresent, OperatingSystem, WindowsDomain, WindowsDomainController, \
    TlsCertificate, DockerRegistryService, VirtualHostname
from shadycompass.facts.port_scanner.nmap import NmapXmlFactReader
from shadycompass.rules.port_scanner.nmap import NmapRules
from tests.tests import assertFactIn, facts_str


class NmapXmlFactReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = NmapXmlFactReader()

    def test_read_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/all/open-ports.xml')
        assertFactIn(
            ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr='10.129.229.189'),
            facts)
        assertFactIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        assertFactIn(TargetHostname(hostname='shadycompass.test'), facts, times=-1)
        assertFactIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=True), facts)
        assertFactIn(SshService(addr='10.129.229.189', port=22), facts)
        assertFactIn(DomainTcpIpService(addr='10.129.229.189', port=53), facts)
        assertFactIn(Kerberos5SecTcpService(addr='10.129.229.189', port=88), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=135), facts)
        assertFactIn(NetbiosSessionService(addr='10.129.229.189', port=139), facts)
        assertFactIn(LdapService(addr='10.129.229.189', port=389, secure=True), facts)
        assertFactIn(HttpService(addr='10.129.229.189', port=443, secure=True), facts)
        assertFactIn(SmbService(addr='10.129.229.189', port=445), facts)
        assertFactIn(Kerberos5SecTcpService(addr='10.129.229.189', port=464), facts)
        assertFactIn(MicrosoftRpcHttpService(addr='10.129.229.189', port=593), facts)
        assertFactIn(LdapService(addr='10.129.229.189', port=636, secure=True), facts)
        assertFactIn(MsmqService(addr='10.129.229.189', port=1801), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=2103), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=2105), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=2107), facts)
        assertFactIn(RdpService(addr='10.129.229.189', port=2179), facts)
        assertFactIn(LdapService(addr='10.129.229.189', port=3268, secure=True), facts)
        assertFactIn(LdapService(addr='10.129.229.189', port=3269, secure=True), facts)
        assertFactIn(RdpService(addr='10.129.229.189', port=3389), facts)
        assertFactIn(WinRMService(addr='10.129.229.189', port=5985, secure=False), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=6404), facts)
        assertFactIn(MicrosoftRpcHttpService(addr='10.129.229.189', port=6406), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=6407), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=6409), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=6616), facts)
        assertFactIn(MicrosoftRpcService(addr='10.129.229.189', port=6637), facts)
        assertFactIn(HttpService(addr='10.129.229.189', port=8080, secure=False), facts)
        assertFactIn(DotNetMessageFramingService(addr='10.129.229.189', port=9389), facts)
        assertFactIn(HostnameIPv4Resolution(hostname='shadycompass.test', addr='10.129.229.189', implied=True), facts)
        assertFactIn(Product(product='apache httpd', version='2.4.56', os_type=OSTYPE_WINDOWS,
                             addr='10.129.229.189', port=443, hostname="www.example.com", secure=True), facts)
        assertFactIn(Product(product='openssl', version='1.1.1t', os_type=OSTYPE_WINDOWS,
                             addr='10.129.229.189', port=443, hostname="www.example.com", secure=True), facts)
        assertFactIn(Product(product='php', version='8.0.28', os_type=OSTYPE_WINDOWS,
                              addr='10.129.229.189', port=443, hostname="www.example.com"), facts)
        assertFactIn(Product(addr='10.129.229.189', product='openssh', os_type='linux', port=22,
                              version='9.0p1 ubuntu 1ubuntu8.5'), facts)
        assertFactIn(
            Product(addr='10.129.229.189', product='simple dns plus', os_type='windows', port=53, secure=False), facts)
        assertFactIn(Product(addr='10.129.229.189', product='microsoft windows kerberos', os_type='windows', port=88),
                      facts)
        assertFactIn(
            Product(addr='10.129.229.189', product='microsoft terminal services', os_type='windows', port=3389,
                    version='10.0.17763'), facts)
        assertFactIn(VirtualHostname(hostname='webmail.shadycompass.test', domain='shadycompass.test'), facts)
        assertFactIn(HostnameIPv4Resolution(hostname='webmail.shadycompass.test', addr='10.129.229.189', implied=True),
                      facts)
        assertFactIn(OperatingSystem(addr='10.129.229.189', port=593, os_type='windows'), facts)
        assertFactIn(OperatingSystem(addr='10.129.229.189', port=22, os_type='linux'), facts)
        assertFactIn(WindowsDomain(
            netbios_domain_name='SHADYCOMPASS',
            dns_domain_name='shadycompass.test',
            dns_tree_name='shadycompass.test',
        ), facts)
        assertFactIn(WindowsDomainController(
            netbios_domain_name='SHADYCOMPASS',
            netbios_computer_name='DC',
            dns_domain_name='shadycompass.test',
            dns_tree_name='shadycompass.test',
            hostname='DC.shadycompass.test',
            addr='10.129.229.189'
        ), facts, times=-1)
        assertFactIn(TlsCertificate(
            subjects=['DC.shadycompass.test'],
            issuer='DC',
        ), facts, times=-1)
        self.assertEqual(88, len(facts), facts_str(facts))

    def test_ignore_not_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/all/open-ports.txt')
        self.assertEqual(0, len(facts))

    def test_ssl_certs_unusual(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/ssl_cert_unusual/nmap-ssl-certs.xml')
        assertFactIn(TlsCertificate(
            subjects=['dc01.shadycompass.test'],
            issuer='shadycompass-DC01-CA',
        ), facts, times=4)
        assertFactIn(TlsCertificate(), facts, times=4)

    def test_docker_registry(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/docker_registry/nmap-docker-registry.xml')
        assertFactIn(DockerRegistryService(addr='10.129.175.32', port=5000, secure=True), facts)

    def test_wordpress_generator(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/wordpress/nmap-wordpress.xml')
        assertFactIn(Product(product='wordpress', version='5.4-alpha-47225',
                             addr='10.129.229.189', port=80), facts)

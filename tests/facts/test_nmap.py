import unittest

from shadycompass.facts import HostnameIPv4Resolution, TargetIPv4Address, TargetHostname, TcpIpService, \
    DomainTcpIpService, HttpService
from shadycompass.facts.nmap import NmapXmlFactReader


class NmapXmlFactReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = NmapXmlFactReader()

    def test_read_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/open-ports.xml')
        self.assertEqual(32, len(facts))
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(TargetHostname(hostname='hospital.htb'), facts)
        self.assertIn(TargetHostname(hostname='hospital.htb'), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=22), facts)
        self.assertIn(DomainTcpIpService(addr='10.129.229.189', port=53), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=88), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=135), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=139), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=389), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=443, secure=True), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=445), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=464), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=593), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=636), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=1801), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=2103), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=2105), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=2107), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=2179), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=3268), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=3269), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=3389), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=5985, secure=False), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6404), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6406), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6407), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6409), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6616), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=6637), facts)
        self.assertIn(HttpService(addr='10.129.229.189', port=8080, secure=False), facts)
        self.assertIn(TcpIpService(addr='10.129.229.189', port=9389), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='hospital.htb', addr='10.129.229.189'), facts)

    def test_ignore_not_xml(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/open-ports.txt')
        self.assertEqual(0, len(facts))

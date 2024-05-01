import unittest

from shadycompass.facts import HostnameIPv4Resolution, HostnameIPv6Resolution
from shadycompass.facts.etc_hosts import EtcHosts


class EtcHostsReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = EtcHosts()

    def test_read_hosts(self):
        facts = self.reader.read_facts('tests/fixtures/etchosts/hosts')
        self.assertEqual(5, len(facts))
        self.assertIn(HostnameIPv4Resolution(hostname='localhost', addr='127.0.0.1', implied=False), facts)
        self.assertIn(HostnameIPv6Resolution(hostname='localhost', addr='::1', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='target1.local', addr='10.10.1.1', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='target2.local', addr='10.10.1.2', implied=False), facts)
        self.assertIn(HostnameIPv4Resolution(hostname='subdomain.target2.local', addr='10.10.1.2', implied=False),
                      facts)

    def test_ignore_not_hosts(self):
        facts = self.reader.read_facts('tests/fixtures/nmap/open-ports.txt')
        self.assertEqual(0, len(facts))

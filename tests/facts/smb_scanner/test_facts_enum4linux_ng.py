import unittest

from shadycompass import TargetHostname
from shadycompass.config import ToolCategory
from shadycompass.facts import WindowsDomain, OperatingSystem, Product, ScanPresent, OSTYPE_WINDOWS, TargetIPv4Address, \
    OSTYPE_LINUX
from shadycompass.facts.smb_scanner.enum4linux_ng import Enum4LinuxNGReader
from shadycompass.rules.smb_scanner.enum4linuxng import Enum4LinuxNgRules


class Enum4LinuxNGReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = Enum4LinuxNGReader()

    def test_windows(self):
        facts = self.reader.read_facts('tests/fixtures/enum4linux_ng/enum4linux-shadycompass.test.json')
        self.assertIn(ScanPresent(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            hostname='shadycompass.test'
        ), facts)
        self.assertIn(TargetHostname(hostname="shadycompass.test"), facts)
        self.assertIn(WindowsDomain(
            netbios_domain_name='SHADYCOMPASS',
            dns_domain_name='shadycompass.test',
        ), facts)
        self.assertIn(OperatingSystem(
            hostname='shadycompass.test',
            os_type=OSTYPE_WINDOWS,
            name='windows 10, windows server 2019, windows server 2016',
            version='10.0.19041',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.02',
            os_type=OSTYPE_WINDOWS,
            hostname='shadycompass.test',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.1',
            os_type=OSTYPE_WINDOWS,
            hostname='shadycompass.test',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='3.0',
            os_type=OSTYPE_WINDOWS,
            hostname='shadycompass.test',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='3.1.1',
            os_type=OSTYPE_WINDOWS,
            hostname='shadycompass.test',
        ), facts)
        self.assertEqual(8, len(facts))

    def test_linux(self):
        facts = self.reader.read_facts('tests/fixtures/enum4linux_ng/enum4linux-linux.json')
        self.assertIn(ScanPresent(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(OperatingSystem(
            addr='10.129.229.189',
            os_type=OSTYPE_LINUX,
            name='linux/unix (samba server)',
            version='6.1.0',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.02',
            os_type=OSTYPE_LINUX,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.1',
            os_type=OSTYPE_LINUX,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='3.0',
            os_type=OSTYPE_LINUX,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='3.1.1',
            os_type=OSTYPE_LINUX,
            addr='10.129.229.189',
        ), facts)
        self.assertEqual(7, len(facts))

    def test_mac(self):
        facts = self.reader.read_facts('tests/fixtures/enum4linux_ng/enum4linux-mac.json')
        self.assertIn(ScanPresent(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(TargetIPv4Address(addr='10.129.229.189'), facts)
        self.assertIn(WindowsDomain(
            dns_domain_name='shadycompass.test',
        ), facts)
        self.assertIn(OperatingSystem(
            addr='10.129.229.189',
            os_type=OSTYPE_WINDOWS,
            name='windows 7, windows server 2008 r2',
            version='6.1.7600',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.02',
            os_type=OSTYPE_WINDOWS,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='2.1',
            os_type=OSTYPE_WINDOWS,
            addr='10.129.229.189',
        ), facts)
        self.assertIn(Product(
            product='smb',
            version='3.0',
            os_type=OSTYPE_WINDOWS,
            addr='10.129.229.189',
        ), facts)
        self.assertEqual(7, len(facts))

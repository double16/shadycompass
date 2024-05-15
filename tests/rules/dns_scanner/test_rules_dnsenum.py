from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION
from shadycompass.facts import ScanNeeded, ScanPresent, TargetDomain, TargetIPv4Address, DomainUdpIpService
from shadycompass.rules.dns_scanner.dnsenum import DnsEnumRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class DnsEnumTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dnsenum_private(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', 'shadycompass.test',
            ],
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53,
                                        name=DnsEnumRules.dnsenum_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.dns_scanner, name=DnsEnumRules.dnsenum_tool_name),
                        self.engine)

    def test_dnsenum_private_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '--threads', '1',
                'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsenum_public(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(DomainUdpIpService(addr='8.8.8.8', port=53))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='8.8.8.8', port=53), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '8.8.8.8',
                '--enum',
                '-o', 'dnsenum-8.8.8.8-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsenum_public_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(DomainUdpIpService(addr='8.8.8.8', port=53))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='8.8.8.8', port=53), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '8.8.8.8',
                '--enum',
                '-o', 'dnsenum-8.8.8.8-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '--threads', '1',
                'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsenum_two_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', 'shadycompass.test',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass2.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', 'shadycompass2.test',
            ],
        ), self.engine)

    def test_dnsenum_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, DnsEnumRules.dnsenum_tool_name, '--nocolor', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '--nocolor',
                'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsenum_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, DnsEnumRules.dnsenum_tool_name, '--nocolor', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
            command_line=[
                '--dnsserver', '10.129.229.189',
                '-p', '0', '-s', '0',
                '-o', 'dnsenum-10.129.229.189-53-subdomains-shadycompass.test.xml',
                '-f', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '--nocolor',
                'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsenum_retract(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsEnumRules.dnsenum_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.dns_scanner, name=DnsEnumRules.dnsenum_tool_name, addr='10.129.229.189',
                        port=53))
        self.engine.run()
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsEnumRules.dnsenum_tool_name,
        ), self.engine)

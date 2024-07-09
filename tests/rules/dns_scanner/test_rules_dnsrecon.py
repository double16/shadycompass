from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION, SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN
from shadycompass.facts import ScanNeeded, ScanPresent, TargetDomain, TargetIPv4Address, DomainUdpIpService
from shadycompass.rules.dns_scanner.dnsrecon import DnsReconRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class DnsReconTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dnsrecon_private(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53,
                                        name=DnsReconRules.dnsrecon_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.dns_scanner, name=DnsReconRules.dnsrecon_tool_name),
                        self.engine)

    def test_dnsrecon_private_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '--threads', '1',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsrecon_public(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(DomainUdpIpService(addr='8.8.8.8', port=53))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='8.8.8.8', port=53), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '8.8.8.8',
                '-a', '-s', '-b', '-y', '-k', '-w', '-z',
                '-j', 'dnsrecon-8.8.8.8-53-shadycompass.test.json',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsrecon_public_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(DomainUdpIpService(addr='8.8.8.8', port=53))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='8.8.8.8', port=53), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '8.8.8.8',
                '-a', '-s', '-b', '-y', '-k', '-w', '-z',
                '-j', 'dnsrecon-8.8.8.8-53-shadycompass.test.json',
                '--threads', '1',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsrecon_two_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass2.test.json',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass2.test',
            ],
        ), self.engine)

    def test_dnsrecon_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, DnsReconRules.dnsrecon_tool_name, '-f', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '-f',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsrecon_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, DnsReconRules.dnsrecon_tool_name, '-f', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '-f',
                '-D', 'subdomains-top1million-110000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)

    def test_dnsrecon_retract(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.dns_scanner, name=DnsReconRules.dnsrecon_tool_name, addr='10.129.229.189',
                        port=53))
        self.engine.run()
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
        ), self.engine)

    def test_dnsrecon_private_wordlist(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DnsReconRules.dnsrecon_tool_name, True)
        self.engine.config_set(SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN, 'subdomains-top1million-5000.txt', True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DnsReconRules.dnsrecon_tool_name,
            command_line=[
                '-n', '10.129.229.189',
                '-j', 'dnsrecon-10.129.229.189-53-shadycompass.test.json',
                '-D', 'subdomains-top1million-5000.txt',
                '-d', 'shadycompass.test',
            ],
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53,
                                        name=DnsReconRules.dnsrecon_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.dns_scanner, name=DnsReconRules.dnsrecon_tool_name),
                        self.engine)

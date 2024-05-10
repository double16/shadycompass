from abc import ABC

from experta import DefFacts, AS, Rule, NOT, MATCH

from shadycompass import ToolAvailable, TargetDomain
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, RateLimitEnable, PublicTarget
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DnsReconRules(IRules, ABC):
    dnsrecon_tool_name = 'dnsrecon'

    @DefFacts()
    def dnsrecon_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dnsrecon_tool_name,
            tool_links=[
                'https://github.com/darkoperator/dnsrecon',
                'https://www.kali.org/tools/dnsrecon/',
            ],
            methodology_links=METHOD_DNS,
        )

    def _declare_dnsrecon(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable = None,
                          public: PublicTarget = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        if public is None:
            enum_options = []
        else:
            enum_options = ['-a', '-s', '-b', '-y', '-k', '-w', '-z']

        more_options = []
        if ratelimit:
            more_options.append(['--threads', '1'])

        command_line = self.resolve_command_line(
            self.dnsrecon_tool_name,
            [
                '-n', f'{f1.get_addr()}:{f1.get_port()}',
                *enum_options,
                '-D', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '-j', f'dnsrecon{addr_file_name_part}-{domain.get_domain()}.json',
            ], *more_options
        )
        command_line.extend(['-d', domain.get_domain()])
        self.recommend_tool(
            category=ToolCategory.dns_scanner,
            name=self.dnsrecon_tool_name,
            variant=domain.get_domain(),
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        TOOL_PREF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
        NOT(PublicTarget(addr=MATCH.addr)),
    )
    def run_dnsrecon(self, f1: ScanNeeded, domain: TargetDomain):
        self._declare_dnsrecon(f1, domain)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.public << PublicTarget(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_dnsrecon_public(self, f1: ScanNeeded, domain: TargetDomain, public: PublicTarget):
        self._declare_dnsrecon(f1, domain, public=public)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        NOT(PublicTarget(addr=MATCH.addr)),
    )
    def run_dnsrecon_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable):
        self._declare_dnsrecon(f1, domain, ratelimit=ratelimit)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.dns_scanner, dnsrecon_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsrecon_tool_name),
    )
    def run_dnsrecon_public_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable,
                                      public: PublicTarget):
        self._declare_dnsrecon(f1, domain, ratelimit=ratelimit, public=public)

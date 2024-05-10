from abc import ABC
from math import floor

from experta import DefFacts, Rule, AS, NOT, MATCH

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, TargetDomain, RateLimitEnable
from shadycompass.rules.conditions import TOOL_CONF, TOOL_PREF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class FierceRules(IRules, ABC):
    fierce_tool_name = 'fierce'

    @DefFacts()
    def dnsrecon_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.fierce_tool_name,
            tool_links=[
                'https://github.com/mschwager/fierce',
                'https://www.kali.org/tools/fierce/',
            ],
            methodology_links=METHOD_DNS,
        )

    def _declare_fierce(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        more_options = []
        if ratelimit:
            more_options.append(['--delay', str(floor(60 / ratelimit.get_request_per_second()))])

        command_line = self.resolve_command_line(
            self.fierce_tool_name,
            [
                '--dns-servers', f'{f1.get_addr()}:{f1.get_port()}',
            ], *more_options
        )
        command_line.extend([
            '--domain', domain.get_domain(),
            f'>fierce{addr_file_name_part}-{domain.get_domain()}.txt'
        ])
        self.recommend_tool(
            category=ToolCategory.dns_scanner,
            name=self.fierce_tool_name,
            variant=domain.get_domain(),
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        TOOL_PREF(ToolCategory.dns_scanner, fierce_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, fierce_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_fierce(self, f1: ScanNeeded, domain: TargetDomain):
        self._declare_fierce(f1, domain)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.dns_scanner, fierce_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, fierce_tool_name),
    )
    def run_fierce_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable):
        self._declare_fierce(f1, domain, ratelimit=ratelimit)

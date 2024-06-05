from abc import ABC

from experta import DefFacts, Rule, AS, NOT, MATCH
from math import floor

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, RateLimitEnable, WindowsDomain
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_ASREP_ROASTING


class KerbruteRules(IRules, ABC):
    kerbrute_tool_name = 'kerbrute'

    @DefFacts()
    def kerbrute_available(self):
        yield ToolAvailable(
            category=ToolCategory.asrep_roaster,
            name=self.kerbrute_tool_name,
            tool_links=[
                'https://github.com/ropnop/kerbrute',
            ],
            methodology_links=METHOD_ASREP_ROASTING,
        )

    # kerbrute --safe passwordspray -d shadycompass.test --dc dc.shadycompass.test users 'Passw0rd!' >kerbrute-passwordspray-shadycompass.test.txt

    def _declare_kerbrute_asrep_roast(self, f1: ScanNeeded, domain: WindowsDomain, ratelimit: RateLimitEnable = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}'
        if domain:
            addr_file_name_part += f'-{domain.get_netbios_domain_name()}'

        global_options = []
        if ratelimit:
            global_options.extend(['--delay', str(floor(60000 / ratelimit.get_request_per_second()))])
        if domain:
            global_options.extend(['-d', domain.get_netbios_domain_name()])

        command_line = self.resolve_command_line(
            self.kerbrute_tool_name,
            [
                '--safe',
                '--dc', f1.get_hostname() or f1.get_addr(),
                *global_options,
                'userenum',
            ],
        )
        command_line.extend([
            '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
            f'>{self.kerbrute_tool_name}-userenum{addr_file_name_part}.txt',
        ])
        self.recommend_tool(
            category=ToolCategory.asrep_roaster,
            name=self.kerbrute_tool_name,
            variant=domain.get_netbios_domain_name() if domain is not None else None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
        AS.domain << WindowsDomain(netbios_domain_name=MATCH.netbios_domain_name),
        TOOL_PREF(ToolCategory.asrep_roaster, kerbrute_tool_name),
        TOOL_CONF(ToolCategory.asrep_roaster, kerbrute_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_kerbrute_asrep_roast_domain(self, f1: ScanNeeded, domain: WindowsDomain):
        self._declare_kerbrute_asrep_roast(f1, domain=domain)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
        AS.domain << WindowsDomain(netbios_domain_name=MATCH.netbios_domain_name),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.asrep_roaster, kerbrute_tool_name),
        TOOL_CONF(ToolCategory.asrep_roaster, kerbrute_tool_name),
    )
    def run_kerbrute_asrep_roast_domain_ratelimit(self, f1: ScanNeeded, domain: WindowsDomain,
                                                  ratelimit: RateLimitEnable):
        self._declare_kerbrute_asrep_roast(f1, domain=domain, ratelimit=ratelimit)

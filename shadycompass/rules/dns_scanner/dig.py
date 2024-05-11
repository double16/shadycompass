from abc import ABC

from experta import DefFacts, Rule, AS, MATCH

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, TargetDomain
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DigRules(IRules, ABC):
    dig_tool_name = 'dig'

    @DefFacts()
    def dig_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dig_tool_name,
            tool_links=[
                'https://www.isc.org/bind/',
            ],
            methodology_links=METHOD_DNS,
        )

    def _declare_dig_any(self, f1: ScanNeeded, domain: TargetDomain):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        command_line = self.resolve_command_line(
            self.dig_tool_name,
            [
                'any', f'@{f1.get_addr()}', '-p', str(f1.get_port()),
            ]
        )
        command_line.extend([domain.get_domain(), f'>dig-any{addr_file_name_part}.txt'])
        self.recommend_tool(
            category=ToolCategory.dns_scanner,
            name=self.dig_tool_name,
            variant=f'{domain.get_domain()}-any',
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    def _declare_dig_axfr(self, f1: ScanNeeded, domain: TargetDomain):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        command_line = self.resolve_command_line(
            self.dig_tool_name,
            [
                'axfr', f'@{f1.get_addr()}', '-p', str(f1.get_port()),
            ]
        )
        command_line.extend([domain.get_domain(), f'>dig-axfr{addr_file_name_part}.txt'])
        self.recommend_tool(
            category=ToolCategory.dns_scanner,
            name=self.dig_tool_name,
            variant=f'{domain.get_domain()}-axfr',
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        TOOL_PREF(ToolCategory.dns_scanner, dig_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dig_tool_name),
    )
    def run_dig(self, f1: ScanNeeded, domain: TargetDomain):
        self._declare_dig_any(f1, domain)
        self._declare_dig_axfr(f1, domain)

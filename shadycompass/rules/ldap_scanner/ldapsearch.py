from abc import ABC

from experta import DefFacts, Rule, MATCH, AS

from shadycompass.config import ToolCategory, ToolAvailable
from shadycompass.facts import ScanNeeded
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_LDAP


class LdapSearchRules(IRules, ABC):
    ldapsearch_tool_name = 'ldapsearch'

    @DefFacts()
    def ldapsearch_available(self):
        yield ToolAvailable(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            tool_links=[
                'https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html',
            ],
            methodology_links=METHOD_LDAP,
        )

    def _declare_ldapsearch(self, f1: ScanNeeded):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        command_line_base = self.resolve_command_line(
            self.ldapsearch_tool_name,
            [
                '-H', f'ldaps://{f1.get_addr()}:{f1.get_port()}', '-x',
            ],
        )
        command_line_base.extend([
            f'>{self.ldapsearch_tool_name}-base{addr_file_name_part}.txt',
        ])
        self.recommend_tool(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            variant='base',
            command_line=command_line_base,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

        command_line_namingcontexts = self.resolve_command_line(
            self.ldapsearch_tool_name,
            [
                '-H', f'ldaps://{f1.get_addr()}:{f1.get_port()}', '-x', '-s', 'base', 'namingcontexts',
            ],
        )
        command_line_namingcontexts.extend([
            f'>{self.ldapsearch_tool_name}-namingcontexts{addr_file_name_part}.txt',
        ])
        self.recommend_tool(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=command_line_namingcontexts,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        TOOL_PREF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        TOOL_CONF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
    )
    def run_ldapsearch(self, f1: ScanNeeded):
        self._declare_ldapsearch(f1)

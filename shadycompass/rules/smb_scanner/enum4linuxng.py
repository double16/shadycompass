from abc import ABC

from experta import DefFacts, Rule, AS, MATCH, OR, NOT

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended, ConfigFact, \
    SECTION_OPTIONS
from shadycompass.facts import ScanNeeded, ScanPresent
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_SMB


class Enum4LinuxNgRules(IRules, ABC):
    enum4linux_ng_tool_name = 'enum4linux-ng'

    @DefFacts()
    def enum4linux_ng_available(self):
        yield ToolAvailable(
            category=ToolCategory.smb_scanner,
            name=self.enum4linux_ng_tool_name,
            tool_links=[
                'https://github.com/cddmp/enum4linux-ng',
                'https://www.kali.org/tools/enum4linux-ng/',
            ],
            methodology_links=METHOD_SMB,
        )

    def _declare_enum4linux_ng(self, f1: ScanNeeded):
        more_options = []
        command_line = self.resolve_command_line(
            self.enum4linux_ng_tool_name,
            ['-oJ', f"enum4linuxng-{f1.get_addr()}", '-A'], *more_options)
        command_line.append(f1.get_addr())
        self.recommend_tool(
            category=ToolCategory.smb_scanner,
            name=self.enum4linux_ng_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smb_scanner, addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.smb_scanner, name=enum4linux_ng_tool_name),
            PreferredTool(category=ToolCategory.smb_scanner, name=OPTION_VALUE_ALL)
        ),
        OR(ConfigFact(section=SECTION_OPTIONS, option=enum4linux_ng_tool_name),
           NOT(ConfigFact(section=SECTION_OPTIONS, option=enum4linux_ng_tool_name)))
    )
    def run_enum4linux_ng(self, f1: ScanNeeded):
        self._declare_enum4linux_ng(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.smb_scanner, name=enum4linux_ng_tool_name, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.smb_scanner, addr=MATCH.addr),
    )
    def retract_enum4linux_ng(self, f1: ToolRecommended):
        self.retract(f1)

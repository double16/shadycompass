from experta import DefFacts, Rule, AS, OR, NOT, MATCH

from shadycompass.config import ToolAvailable, ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent
from shadycompass.rules.library import METHOD_HTTP_AUTOMATIC_SCANNERS


class NucleiRules:
    nuclei_tool_name = "nuclei"

    @DefFacts()
    def nuclei_available(self):
        yield ToolAvailable(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name,
            tool_links=[
                'https://github.com/projectdiscovery/nuclei'
            ],
            methodology_links=METHOD_HTTP_AUTOMATIC_SCANNERS,
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.vuln_scanner),
        OR(
            PreferredTool(category=ToolCategory.vuln_scanner, name=nuclei_tool_name),
            PreferredTool(category=ToolCategory.vuln_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.vuln_scanner)),
        )
    )
    def run_nuclei(self, f1: ScanNeeded):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'

        command_line = self.resolve_command_line(
            self.nuclei_tool_name,
            [
                '-target', addr, '-json-export', f'nuclei-{addr}.json'
            ]
        )
        self.declare(ToolRecommended(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name,
            command_line=command_line,
            addr=f1.get_addr(),
        ))

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.vuln_scanner, name=nuclei_tool_name, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
    )
    def do_no_run_nuclei(self, f1):
        self.retract(f1)

from experta import DefFacts, Rule, AS, OR, NOT, MATCH

from shadycompass.config import ToolAvailable, ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import VulnScanNeeded, VulnScanPresent
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
        AS.f1 << VulnScanNeeded(),
        OR(
            PreferredTool(category=ToolCategory.vuln_scanner, name=nuclei_tool_name),
            PreferredTool(category=ToolCategory.vuln_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.vuln_scanner)),
        )
    )
    def run_nuclei(self, f1: VulnScanNeeded):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'
        self.declare(ToolRecommended(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name,
            command_line=[
                '-target', addr, '-json-export', f'nuclei-{addr}.json'
            ],
            addr=f1.get_addr(),
        ))

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.vuln_scanner, name=nuclei_tool_name, addr=MATCH.addr),
        VulnScanPresent(addr=MATCH.addr),
    )
    def do_no_run_nuclei(self, f1):
        self.retract(f1)

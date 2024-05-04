from abc import ABC

from experta import DefFacts, Rule, AS, OR, NOT, MATCH

from shadycompass.config import ToolAvailable, ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, RateLimitEnable
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_AUTOMATIC_SCANNERS


class NucleiRules(IRules, ABC):
    nuclei_tool_name = "nuclei"

    @DefFacts()
    def nuclei_available(self):
        yield ToolAvailable(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name,
            tool_links=[
                'https://github.com/projectdiscovery/nuclei',
                'https://www.kali.org/tools/nuclei/',
            ],
            methodology_links=METHOD_HTTP_AUTOMATIC_SCANNERS,
        )

    def _declare_nuclei(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'

        more_options = []
        if ratelimit:
            more_options.append(['-rate-limit', str(ratelimit.get_request_per_second())])

        command_line = self.resolve_command_line(
            self.nuclei_tool_name,
            [
                '-target', addr, '-json-export', f'nuclei-{addr}.json'
            ], *more_options
        )
        self.recommend_tool(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            hostname=f1.get_hostname(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.vuln_scanner, name=nuclei_tool_name),
            PreferredTool(category=ToolCategory.vuln_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.vuln_scanner)),
        ),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_nuclei(self, f1: ScanNeeded):
        self._declare_nuclei(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.vuln_scanner, name=nuclei_tool_name),
            PreferredTool(category=ToolCategory.vuln_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.vuln_scanner)),
        ),
    )
    def run_nuclei_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable):
        self._declare_nuclei(f1, ratelimit)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.vuln_scanner, name=nuclei_tool_name, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
    )
    def do_no_run_nuclei(self, f1):
        self.retract(f1)

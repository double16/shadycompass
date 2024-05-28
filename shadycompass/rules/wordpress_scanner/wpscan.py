from abc import ABC
from math import floor

from experta import DefFacts, MATCH, AS, Rule, NOT

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, RateLimitEnable
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_WORDPRESS


class WpscanRules(IRules, ABC):
    wpscan_name = 'wpscan'

    @DefFacts()
    def wpscan_available(self):
        yield ToolAvailable(
            category=ToolCategory.wordpress_scanner,
            name=self.wpscan_name,
            tool_links=[
                'https://wpscan.com/wordpress-security-scanner',
                'https://www.kali.org/tools/wpscan/',
            ],
            methodology_links=METHOD_WORDPRESS,
        )

    def _declare_wpscan(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None):
        if f1.is_secure():
            protocol = "https"
        else:
            protocol = "http"
        url = f"{protocol}://{f1.get_hostname() or f1.get_addr()}:{f1.get_port()}"

        more_options = []
        if ratelimit:
            more_options.append(['--throttle', str(floor(60000 / ratelimit.get_request_per_second()))])
        command_line = self.resolve_command_line(
            self.wpscan_name,
            [], *more_options
        )
        command_line.extend([
            '--url', url,
            '-o', f"wpscan-{f1.get_port()}-{f1.get_hostname() or f1.get_addr()}.json",
        ])
        self.recommend_tool(
            category=ToolCategory.wordpress_scanner,
            name=self.wpscan_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_hostname(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.wordpress_scanner, addr=MATCH.addr),
        TOOL_PREF(ToolCategory.wordpress_scanner, wpscan_name),
        TOOL_CONF(ToolCategory.wordpress_scanner, wpscan_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_wpscan_addr(self, f1: ScanNeeded):
        self._declare_wpscan(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.wordpress_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.wordpress_scanner, wpscan_name),
        TOOL_CONF(ToolCategory.wordpress_scanner, wpscan_name),
    )
    def run_wpscan_addr_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None):
        self._declare_wpscan(f1, ratelimit)

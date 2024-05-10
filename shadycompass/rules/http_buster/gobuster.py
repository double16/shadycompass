from abc import ABC
from math import floor

from experta import Rule, DefFacts, AS, MATCH, NOT

from shadycompass.config import ToolCategory, ToolAvailable
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class GoBusterRules(IRules, ABC):
    gobuster_tool_name = 'gobuster'

    @DefFacts()
    def gobuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            tool_links=[
                'https://github.com/OJ/gobuster',
                'https://www.kali.org/tools/gobuster/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    def _declare_gobuster(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None):
        more_options = []
        if ratelimit:
            more_options.append(
                ['--threads', '1', '--delay', str(floor(60000 / ratelimit.get_request_per_second())) + "ms"])
        command_line = self.resolve_command_line(
            self.gobuster_tool_name,
            [
                'dir', '-k',
                '-o', f"gobuster-{f1.get_port()}-{f1.get_vhost()}.txt",
                '-u', f1.get_url(),
            ], *more_options
        )
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_gobuster(self, f1: HttpBustingNeeded):
        self._declare_gobuster(f1)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
    )
    def run_gobuster_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None):
        self._declare_gobuster(f1, ratelimit)

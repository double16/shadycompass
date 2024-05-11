from abc import ABC
from math import floor

from experta import Rule, DefFacts, AS, MATCH, NOT

from shadycompass.config import ToolCategory, ToolAvailable
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class DirbRules(IRules, ABC):
    dirb_tool_name = 'dirb'

    @DefFacts()
    def dirb_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.dirb_tool_name,
            tool_links=[
                'https://dirb.sourceforge.net/',
                'https://www.kali.org/tools/dirb/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    def _declare_dirb(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None):
        more_options = []
        if ratelimit:
            more_options.append(['-z', str(floor(60000 / ratelimit.get_request_per_second()))])
        command_line = self.resolve_command_line(
            self.dirb_tool_name,
            [f1.get_url(), '-o', f"dirb-{f1.get_port()}-{f1.get_vhost()}.txt"], *more_options)
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.dirb_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, dirb_tool_name),
        TOOL_CONF(ToolCategory.http_buster, dirb_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_dirb(self, f1: HttpBustingNeeded):
        self._declare_dirb(f1)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, dirb_tool_name),
        TOOL_CONF(ToolCategory.http_buster, dirb_tool_name),
    )
    def run_dirb_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable):
        self._declare_dirb(f1, ratelimit=ratelimit)

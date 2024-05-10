from abc import ABC
from math import floor

from experta import Rule, DefFacts, AS, NOT, MATCH

from shadycompass.config import ToolCategory, ToolAvailable
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class WfuzzRules(IRules, ABC):
    wfuzz_tool_name = 'wfuzz'

    @DefFacts()
    def wfuzz_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            tool_links=[
                'http://www.edge-security.com/wfuzz.php',
                'https://www.kali.org/tools/wfuzz/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    def _declare_wfuzz(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None):
        more_options = []
        if ratelimit:
            more_options.append(['-t', '1', '-s', str(floor(60 / ratelimit.get_request_per_second()))])
        command_line = self.resolve_command_line(
            self.wfuzz_tool_name,
            [
                '-w', '/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt',
                '--hc', '404',
                '-f', f'wfuzz-{f1.get_port()}-{f1.get_vhost()}.json,json',
            ], *more_options
        )
        command_line.append(f'{f1.get_url()}/FUZZ')
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_wfuzz(self, f1: HttpBustingNeeded):
        self._declare_wfuzz(f1)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
    )
    def run_wfuzz_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable):
        self._declare_wfuzz(f1, ratelimit)

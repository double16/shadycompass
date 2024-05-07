from abc import ABC

from experta import Rule, DefFacts, OR, AS, MATCH, NOT

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ConfigFact, \
    SECTION_OPTIONS
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class FeroxBusterRules(IRules, ABC):
    feroxbuster_tool_name = 'feroxbuster'

    @DefFacts()
    def feroxbuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.feroxbuster_tool_name,
            tool_links=[
                'https://github.com/epi052/feroxbuster',
                'https://www.kali.org/tools/feroxbuster/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    def _declare_feroxbuster(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None):
        more_options = []
        if ratelimit:
            more_options.append(['--scan-limit', '1', '--rate-limit', str(ratelimit.get_request_per_second())])
        command_line = self.resolve_command_line(
            self.feroxbuster_tool_name,
            [
                '-u', f1.get_url(),
                '-o', f"feroxbuster-{f1.get_port()}-{f1.get_vhost()}.txt",
                '--insecure',
                '--scan-limit', '4'
            ], *more_options)
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.feroxbuster_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        OR(PreferredTool(category=ToolCategory.http_buster, name=feroxbuster_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL)),
        OR(ConfigFact(section=SECTION_OPTIONS, option=feroxbuster_tool_name),
           NOT(ConfigFact(section=SECTION_OPTIONS, option=feroxbuster_tool_name))),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_feroxbuster(self, f1: HttpBustingNeeded):
        self._declare_feroxbuster(f1)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        OR(PreferredTool(category=ToolCategory.http_buster, name=feroxbuster_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL)),
        OR(ConfigFact(section=SECTION_OPTIONS, option=feroxbuster_tool_name),
           NOT(ConfigFact(section=SECTION_OPTIONS, option=feroxbuster_tool_name))),
    )
    def run_feroxbuster_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable):
        self._declare_feroxbuster(f1, ratelimit=ratelimit)

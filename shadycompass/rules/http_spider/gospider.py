from abc import ABC
from math import floor

from experta import DefFacts, AS, Rule, NOT, MATCH

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import RateLimitEnable, PublicTarget, ScanNeeded
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_AUTOMATIC_SCANNERS


class GospiderRules(IRules, ABC):
    gospider_tool_name = 'gospider'

    @DefFacts()
    def gospider_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_spider,
            name=self.gospider_tool_name,
            tool_links=[
                'https://github.com/jaeles-project/gospider',
            ],
            methodology_links=METHOD_HTTP_AUTOMATIC_SCANNERS,
        )

    def _declare_gospider(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None, public: PublicTarget = None):
        more_options = []
        if ratelimit:
            more_options.append(['--concurrent', '1', '--delay', str(floor(60 / ratelimit.get_request_per_second()))])
        else:
            more_options.append(['--concurrent', '4'])
        if public:
            more_options.append(['--include-other-source'])
        command_line = self.resolve_command_line(
            self.gospider_tool_name,
            [
                '--site', f1.get_url(),
                '--user-agent', 'web',
                '--js', '--sitemap', '--robots',
                '--depth', '3',
                '-o', f"gospider-{f1.get_port()}-{f1.get_hostname()}", '--json',
            ], *more_options)
        self.recommend_tool(
            category=ToolCategory.http_spider,
            name=self.gospider_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_hostname(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, gospider_tool_name),
        TOOL_CONF(ToolCategory.http_spider, gospider_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
        NOT(PublicTarget(addr=MATCH.addr))
    )
    def run_gospider_private(self, f1: ScanNeeded):
        self._declare_gospider(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, gospider_tool_name),
        TOOL_CONF(ToolCategory.http_spider, gospider_tool_name),
        NOT(PublicTarget(addr=MATCH.addr))
    )
    def run_gospider_private_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable):
        self._declare_gospider(f1, ratelimit=ratelimit)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, gospider_tool_name),
        TOOL_CONF(ToolCategory.http_spider, gospider_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_gospider_public(self, f1: ScanNeeded, public: PublicTarget):
        self._declare_gospider(f1, public=public)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, gospider_tool_name),
        TOOL_CONF(ToolCategory.http_spider, gospider_tool_name),
    )
    def run_gospider_public_ratelimit(self, f1: ScanNeeded, public: PublicTarget, ratelimit: RateLimitEnable):
        self._declare_gospider(f1, public=public, ratelimit=ratelimit)

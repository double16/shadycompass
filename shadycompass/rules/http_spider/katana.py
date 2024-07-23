from abc import ABC

from experta import DefFacts, Rule, AS, MATCH, NOT

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, RateLimitEnable, PublicTarget
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_AUTOMATIC_SCANNERS


class KatanaRules(IRules, ABC):
    katana_tool_name = 'katana'

    @DefFacts()
    def katana_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_spider,
            name=self.katana_tool_name,
            tool_links=[
                'https://github.com/projectdiscovery/katana',
            ],
            methodology_links=METHOD_HTTP_AUTOMATIC_SCANNERS,
        )

    def _declare_katana(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None, public: PublicTarget = None):
        pass

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, katana_tool_name),
        TOOL_CONF(ToolCategory.http_spider, katana_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
        NOT(PublicTarget(addr=MATCH.addr))
    )
    def run_katana_private(self, f1: ScanNeeded):
        self._declare_katana(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, katana_tool_name),
        TOOL_CONF(ToolCategory.http_spider, katana_tool_name),
        NOT(PublicTarget(addr=MATCH.addr))
    )
    def run_katana_private_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable):
        self._declare_katana(f1, ratelimit=ratelimit)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, katana_tool_name),
        TOOL_CONF(ToolCategory.http_spider, katana_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_katana_public(self, f1: ScanNeeded, public: PublicTarget):
        self._declare_katana(f1, public=public)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        TOOL_PREF(ToolCategory.http_spider, katana_tool_name),
        TOOL_CONF(ToolCategory.http_spider, katana_tool_name),
    )
    def run_katana_public_ratelimit(self, f1: ScanNeeded, public: PublicTarget, ratelimit: RateLimitEnable):
        self._declare_katana(f1, public=public, ratelimit=ratelimit)

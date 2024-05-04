from abc import ABC

from experta import Rule, AS, MATCH, OR, NOT, P

from shadycompass import ConfigFact
from shadycompass.config import SECTION_DEFAULT, OPTION_PRODUCTION, OPTION_RATELIMIT
from shadycompass.facts import ProductionTarget, TargetIPv4Address, TargetIPv6Address, RateLimitEnable, ScanNeeded
from shadycompass.rules.irules import IRules

TRUTHY = P(lambda v: str(v).lower() in ['true', 't', '1'])
NOT_TRUTHY = P(lambda v: v is None or str(v).lower() in ['false', 'f', '0'])


class ProductionTargetRules(IRules, ABC):

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=TRUTHY),
        AS.target << TargetIPv4Address(),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False)),
    )
    def production_target_ipv4(self, target: TargetIPv4Address):
        self.declare(ProductionTarget(addr=target.get_addr()))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=TRUTHY),
        AS.target << TargetIPv6Address(),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False)),
    )
    def production_target_ipv6(self, target: TargetIPv6Address):
        self.declare(ProductionTarget(addr=target.get_addr()))

    @Rule(
        AS.f1 << ProductionTarget(addr=MATCH.addr),
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False),
        salience=100,
    )
    def non_production_target_local(self, f1):
        self.retract(f1)

    @Rule(
        AS.f1 << ProductionTarget(addr=MATCH.addr),
        OR(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=True),
           NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, global0=True))),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, global0=False))
    )
    def non_production_target(self, f1):
        self.retract(f1)


class RateLimitRules(IRules, ABC):

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        salience=100,
    )
    def ratelimit_target_local_any(self, ratelimit: str):
        self.declare(RateLimitEnable(addr=ScanNeeded.ANY, request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        AS.target << TargetIPv4Address(addr=MATCH.addr),
        salience=100,
    )
    def ratelimit_target_local_ipv4(self, target: TargetIPv4Address, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        AS.target << TargetIPv6Address(addr=MATCH.addr),
        salience=100,
    )
    def ratelimit_target_local_ipv6(self, target: TargetIPv6Address, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=True),
        AS.target << ProductionTarget(addr=MATCH.addr),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, global0=False)),
    )
    def ratelimit_target_global(self, target: ProductionTarget, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        AS.f1 << RateLimitEnable(addr=MATCH.addr),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT)),
    )
    def non_ratelimit_target(self, f1):
        self.retract(f1)

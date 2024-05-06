from shadycompass.config import SECTION_DEFAULT, OPTION_PRODUCTION, OPTION_RATELIMIT
from shadycompass.facts import RateLimitEnable, ScanNeeded, TargetIPv4Address, TargetIPv6Address
from tests.rules.base import RulesBase
from tests.tests import assertFactNotIn, assertFactIn


class RateLimitRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_default_no_ratelimit(self):
        assertFactNotIn(RateLimitEnable(), self.engine)

    def test_global_non_prod_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.run()
        assertFactNotIn(RateLimitEnable(), self.engine)

    def test_local_non_prod_local_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(addr=ScanNeeded.ANY, request_per_second=10), self.engine)
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)

    def test_local_override_global_non_prod(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)
        assertFactIn(RateLimitEnable(addr=ScanNeeded.ANY, request_per_second=10), self.engine)

    def test_global_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=5), self.engine)

    def test_local_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)

    def test_local_override_global(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)

    def test_global_ratelimit_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=5), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_RATELIMIT, True)
        self.engine.run()
        assertFactNotIn(RateLimitEnable(), self.engine)

    def test_local_ratelimit_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_RATELIMIT, False)
        self.engine.run()
        assertFactNotIn(RateLimitEnable(), self.engine)

    def test_local_override_global_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '10', False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=10), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_RATELIMIT, False)
        self.engine.run()
        assertFactIn(RateLimitEnable(request_per_second=5), self.engine)

    def test_ratelimit_public_ip(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(TargetIPv6Address(addr='2607:f8b0:4002:c1b::6a'))
        self.engine.run()
        assertFactNotIn(RateLimitEnable(addr='10.1.1.1', request_per_second=5), self.engine)
        assertFactIn(RateLimitEnable(addr='8.8.8.8', request_per_second=5), self.engine)
        assertFactIn(RateLimitEnable(addr='2607:f8b0:4002:c1b::6a', request_per_second=5), self.engine)

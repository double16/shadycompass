from base import RulesBase
from shadycompass import TargetIPv4Address, ConfigFact
from shadycompass.config import SECTION_DEFAULT, OPTION_PRODUCTION
from shadycompass.facts import PublicTarget, TargetIPv6Address, ProductionTarget
from tests.tests import assertFactIn, assertFactNotIn


class PublicAddrRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_private_ip4(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='192.168.1.1'))
        self.engine.declare(TargetIPv4Address(addr='127.0.0.1'))
        self.engine.declare(TargetIPv4Address(addr='127.0.0.2'))
        self.engine.run()
        assertFactNotIn(PublicTarget(addr='10.1.1.1'), self.engine)
        assertFactNotIn(PublicTarget(addr='192.168.1.1'), self.engine)
        assertFactNotIn(PublicTarget(addr='127.0.0.1'), self.engine)
        assertFactNotIn(PublicTarget(addr='127.0.0.2'), self.engine)
        assertFactNotIn(ProductionTarget(addr='10.1.1.1'), self.engine)
        assertFactNotIn(ProductionTarget(addr='192.168.1.1'), self.engine)
        assertFactNotIn(ProductionTarget(addr='127.0.0.1'), self.engine)
        assertFactNotIn(ProductionTarget(addr='127.0.0.2'), self.engine)

    def test_private_ipv6(self):
        self.engine.declare(TargetIPv6Address(addr='::1'))
        self.engine.run()
        assertFactNotIn(PublicTarget(addr='::1'), self.engine)
        assertFactNotIn(ProductionTarget(addr='::1'), self.engine)

    def test_public_ipv4(self):
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.run()
        assertFactNotIn(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION), self.engine)
        assertFactIn(PublicTarget(addr='8.8.8.8'), self.engine)
        assertFactIn(ProductionTarget(addr='8.8.8.8'), self.engine)

    def test_public_ipv6(self):
        self.engine.declare(TargetIPv6Address(addr='2607:f8b0:4002:c1b::6a'))
        self.engine.run()
        assertFactNotIn(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION), self.engine)
        assertFactIn(PublicTarget(addr='2607:f8b0:4002:c1b::6a'), self.engine)
        assertFactIn(ProductionTarget(addr='2607:f8b0:4002:c1b::6a'), self.engine)

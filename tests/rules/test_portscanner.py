from base import RulesBase
from shadycompass.facts import PortScanNeeded, TargetIPv4Address
from tests.tests import assertFactIn, assertFactNotIn


class PortScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_portscan_no_targets(self):
        assertFactIn(PortScanNeeded(addr=PortScanNeeded.ANY), self.engine)

    def test_portscan_one_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(PortScanNeeded(addr=PortScanNeeded.ANY), self.engine)
        assertFactIn(PortScanNeeded(addr='10.1.1.1'), self.engine)

    def test_portscan_two_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.2'))
        self.engine.run()
        assertFactNotIn(PortScanNeeded(addr=PortScanNeeded.ANY), self.engine)
        assertFactIn(PortScanNeeded(addr='10.1.1.1'), self.engine)
        assertFactIn(PortScanNeeded(addr='10.1.1.2'), self.engine)


class PortScanNotNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_portscan_not_needed(self):
        assertFactNotIn(PortScanNeeded(), self.engine)

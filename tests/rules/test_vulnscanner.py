from base import RulesBase
from shadycompass.facts import VulnScanNeeded, TargetIPv4Address, VulnScanPresent
from tests.tests import assertFactIn, assertFactNotIn


class VulnScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_vulnscan_no_targets(self):
        assertFactIn(VulnScanNeeded(addr=VulnScanNeeded.ANY), self.engine)

    def test_vulnscan_one_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(VulnScanNeeded(addr=VulnScanNeeded.ANY), self.engine)
        assertFactIn(VulnScanNeeded(addr='10.1.1.1'), self.engine)

    def test_vulnscan_two_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.2'))
        self.engine.run()
        assertFactNotIn(VulnScanNeeded(addr=VulnScanNeeded.ANY), self.engine)
        assertFactIn(VulnScanNeeded(addr='10.1.1.1'), self.engine)
        assertFactIn(VulnScanNeeded(addr='10.1.1.2'), self.engine)

    def test_vulnscan_present(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(VulnScanPresent(name='nuclei', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(VulnScanNeeded(addr=VulnScanNeeded.ANY), self.engine)
        assertFactNotIn(VulnScanNeeded(addr='10.1.1.1'), self.engine)

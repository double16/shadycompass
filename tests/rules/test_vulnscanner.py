from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, TargetIPv4Address, ScanPresent
from tests.tests import assertFactIn, assertFactNotIn


class VulnScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_vulnscan_no_targets(self):
        assertFactIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY), self.engine)

    def test_vulnscan_one_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr='10.1.1.1'), self.engine)

    def test_vulnscan_two_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.2'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr='10.1.1.1'), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr='10.1.1.2'), self.engine)

    def test_vulnscan_present(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(ScanPresent(category=ToolCategory.vuln_scanner, name='nuclei', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.vuln_scanner, addr='10.1.1.1'), self.engine)

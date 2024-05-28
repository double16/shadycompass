from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, TargetIPv4Address, ScanPresent
from shadycompass.rules.port_scanner.nmap import NmapRules
from tests.tests import assertFactIn, assertFactNotIn


class PortScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_portscan_no_targets(self):
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY), self.engine)

    def test_portscan_one_target(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.1'), self.engine)

    def test_portscan_two_targets(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.2'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.1'), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.2'), self.engine)

    def test_portscan_present(self):
        self.engine.declare(ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.1'), self.engine)


class PortScanNotNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_portscan_not_needed(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)

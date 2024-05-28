from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, PopService
from tests.tests import assertFactIn, assertFactNotIn


class PopScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_popscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner), self.engine)

    def test_popscan_one_target(self):
        self.engine.declare(PopService(addr='10.1.1.1', port=110, secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.1.1.1', port=110, secure=False),
                     self.engine)

    def test_popscan_two_targets(self):
        self.engine.declare(PopService(addr='10.1.1.1', port=110, secure=False))
        self.engine.declare(PopService(addr='10.1.1.2', port=110, secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.1.1.1', port=110, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.1.1.2', port=110, secure=False),
                     self.engine)

    def test_popscan_present1(self):
        self.engine.declare(PopService(addr='10.1.1.1', port=110, secure=False))
        self.engine.declare(ScanPresent(category=ToolCategory.pop_scanner, name='nmap', addr='10.1.1.1', port=110))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.1.1.1', port=110), self.engine)

    def test_popscan_present2(self):
        self.engine.declare(PopService(addr='10.1.1.1', port=110, secure=False))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.pop_scanner, name='nmap', addr='10.1.1.1', port=110))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.1.1.1', port=110), self.engine)

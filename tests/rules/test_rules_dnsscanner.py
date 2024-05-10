from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, DomainTcpIpService, DomainUdpIpService
from tests.tests import assertFactIn, assertFactNotIn


class DnsScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_dnsscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)

    def test_dnsscan_one_target(self):
        self.engine.declare(DomainTcpIpService(addr='10.1.1.1', port=53))
        self.engine.declare(DomainUdpIpService(addr='10.1.1.1', port=53))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.1.1.1', port=53),
                     self.engine)

    def test_dnsscan_two_target(self):
        self.engine.declare(DomainUdpIpService(addr='10.1.1.1', port=53))
        self.engine.declare(DomainUdpIpService(addr='10.1.1.2', port=53))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.1.1.1', port=53),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.1.1.2', port=53),
                     self.engine)

    def test_dnsscan_present1(self):
        self.engine.declare(DomainUdpIpService(addr='10.1.1.1', port=53))
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, name='nmap', addr='10.1.1.1', port=53))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.1.1.1', port=53), self.engine)

    def test_dnsscan_present2(self):
        self.engine.declare(DomainUdpIpService(addr='10.1.1.1', port=53))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, name='nmap', addr='10.1.1.1', port=53))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.1.1.1', port=53), self.engine)

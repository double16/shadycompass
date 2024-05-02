from experta import Rule, NOT, OR, MATCH, AS, EXISTS

from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, TargetIPv4Address, TargetIPv6Address


class VulnScan:
    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        NOT(ScanPresent(category=ToolCategory.vuln_scanner, addr=MATCH.addr)),
        salience=100
    )
    def need_vuln_scan_addr(self, addr):
        self.declare(ScanNeeded(category=ToolCategory.vuln_scanner, addr=addr))

    @Rule(
        NOT(ScanPresent(category=ToolCategory.vuln_scanner)),
        NOT(ScanNeeded(category=ToolCategory.vuln_scanner))
    )
    def need_vuln_scan(self):
        self.declare(ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.vuln_scanner, addr=MATCH.addr),
        )
    def do_not_need_vuln_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.vuln_scanner, addr=ScanNeeded.ANY),
        OR(EXISTS(TargetIPv4Address()), EXISTS(TargetIPv6Address())),
        )
    def do_not_need_general_vuln_scan(self, f1: ScanNeeded):
        self.retract(f1)

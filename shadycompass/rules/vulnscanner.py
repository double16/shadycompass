from experta import Rule, NOT, OR, MATCH, AS, EXISTS

from shadycompass.facts import VulnScanNeeded, VulnScanPresent, TargetIPv4Address, TargetIPv6Address


class VulnScan:
    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        NOT(VulnScanPresent(addr=MATCH.addr)),
        salience=100
    )
    def need_vuln_scan_addr(self, addr):
        self.declare(VulnScanNeeded(addr=addr))

    @Rule(
        NOT(VulnScanPresent()),
        NOT(VulnScanNeeded())
    )
    def need_vuln_scan(self):
        self.declare(VulnScanNeeded(addr=VulnScanNeeded.ANY))

    @Rule(
        AS.f1 << VulnScanNeeded(addr=MATCH.addr),
        VulnScanPresent(addr=MATCH.addr),
        )
    def do_not_need_vuln_scan(self, f1: VulnScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << VulnScanNeeded(addr=VulnScanNeeded.ANY),
        OR(EXISTS(TargetIPv4Address()), EXISTS(TargetIPv6Address())),
        )
    def do_not_need_general_vuln_scan(self, f1: VulnScanNeeded):
        self.retract(f1)

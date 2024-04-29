from experta import Rule, NOT, OR, MATCH, AS, EXISTS

from shadycompass.facts import TcpIpService, UdpIpService, PortScanNeeded, TargetIPv4Address, TargetIPv6Address


class PortScan:
    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        NOT(OR(TcpIpService(), UdpIpService())),
        salience=100
    )
    def need_port_scan_addr(self, addr):
        self.declare(PortScanNeeded(addr=addr))

    @Rule(
        NOT(OR(TcpIpService(), UdpIpService())),
        NOT(PortScanNeeded())
    )
    def need_port_scan(self):
        self.declare(PortScanNeeded(addr=PortScanNeeded.ANY))

    @Rule(
        AS.f1 << PortScanNeeded(addr=MATCH.addr),
        OR(TcpIpService(addr=MATCH.addr), UdpIpService(addr=MATCH.addr)),
    )
    def do_not_need_port_scan(self, f1: PortScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << PortScanNeeded(addr=PortScanNeeded.ANY),
        OR(EXISTS(TargetIPv4Address()), EXISTS(TargetIPv6Address())),
        )
    def do_not_need_general_port_scan(self, f1: PortScanNeeded):
        self.retract(f1)

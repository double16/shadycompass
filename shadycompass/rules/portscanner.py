from abc import ABC

from experta import Rule, NOT, OR, MATCH, AS, EXISTS

from shadycompass.config import ToolCategory
from shadycompass.facts import TcpIpService, UdpIpService, ScanNeeded, TargetIPv4Address, TargetIPv6Address, \
    ScanPresent
from shadycompass.rules.irules import IRules


class PortScan(IRules, ABC):
    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        NOT(OR(TcpIpService(addr=MATCH.addr), UdpIpService(addr=MATCH.addr))),
        salience=100
    )
    def need_port_scan_addr(self, addr):
        self.declare(ScanNeeded(category=ToolCategory.port_scanner, addr=addr))

    @Rule(
        NOT(OR(TcpIpService(), UdpIpService(), ScanPresent(category=ToolCategory.port_scanner))),
        NOT(ScanNeeded(category=ToolCategory.port_scanner))
    )
    def need_port_scan(self):
        self.declare(ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.port_scanner, addr=MATCH.addr),
        OR(TcpIpService(addr=MATCH.addr), UdpIpService(addr=MATCH.addr), ScanPresent(category=ToolCategory.port_scanner, addr=MATCH.addr)),
    )
    def do_not_need_port_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.port_scanner, addr=ScanNeeded.ANY),
        OR(EXISTS(TargetIPv4Address()), EXISTS(TargetIPv6Address()), EXISTS(ScanPresent(category=ToolCategory.port_scanner))),
        )
    def do_not_need_general_port_scan(self, f1: ScanNeeded):
        self.retract(f1)

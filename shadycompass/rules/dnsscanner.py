from abc import ABC

from experta import Rule, NOT, MATCH, AS, OR

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, DomainTcpIpService, DomainUdpIpService
from shadycompass.rules.irules import IRules


class DnsScan(IRules, ABC):
    @Rule(
        OR(
            DomainTcpIpService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
            DomainUdpIpService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure)),
        NOT(ScanPresent(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=MATCH.port)),
        salience=100
    )
    def need_dns_scan_addr(self, addr: str, port: int, secure: bool):
        self.declare(ScanNeeded(category=ToolCategory.dns_scanner, addr=addr, port=port, secure=secure))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def do_not_need_dns_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def retract_dns(self, f1: ToolRecommended):
        self.retract(f1)

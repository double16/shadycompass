from abc import ABC

from experta import Rule, NOT, MATCH, AS, OR

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, HttpService, HostnameIPv6Resolution, \
    HostnameIPv4Resolution
from shadycompass.rules.irules import IRules


class VirtualHostScan(IRules, ABC):
    @Rule(
        HttpService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
        OR(
            HostnameIPv4Resolution(hostname=MATCH.hostname, addr=MATCH.addr),
            HostnameIPv6Resolution(hostname=MATCH.hostname, addr=MATCH.addr)),
        NOT(ScanPresent(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr, port=MATCH.port,
                        hostname=MATCH.hostname)),
        salience=100
    )
    def need_virtualhost_scan_addr(self, addr: str, port: int, hostname: str, secure: bool):
        protocol = 'https' if secure else 'http'
        url = f"{protocol}://{hostname}:{port}"
        self.declare(ScanNeeded(
            category=ToolCategory.virtualhost_scanner, addr=addr, port=port, hostname=hostname, secure=secure, url=url))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr, port=MATCH.port,
                            hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr, port=MATCH.port,
                    hostname=MATCH.hostname),
    )
    def do_not_need_virtualhost_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr, port=MATCH.port,
                                 hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr, port=MATCH.port,
                    hostname=MATCH.hostname),
    )
    def retract_virtualhost_scan_tool(self, f1: ToolRecommended):
        self.retract(f1)

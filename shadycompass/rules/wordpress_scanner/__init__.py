from abc import ABC

from experta import Rule, NOT, MATCH, AS, OR, CONTAINS

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, TargetIPv4Address, TargetIPv6Address, Product, \
    VirtualHostname, HostnameIPv4Resolution, HostnameIPv6Resolution
from shadycompass.rules.irules import IRules


class WordpressScan(IRules, ABC):
    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        Product(product=CONTAINS('wordpress'), addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
        NOT(ScanPresent(category=ToolCategory.wordpress_scanner, addr=MATCH.addr, port=MATCH.port)),
        NOT(OR(HostnameIPv4Resolution(addr=MATCH.addr), HostnameIPv6Resolution(addr=MATCH.addr))),
        salience=100
    )
    def need_wordpress_scan_addr(self, addr: str, port: int, secure: bool):
        self.declare(ScanNeeded(category=ToolCategory.wordpress_scanner, addr=addr, port=port, secure=secure))

    @Rule(
        VirtualHostname(hostname=MATCH.hostname, port=MATCH.port, secure=MATCH.secure, domain=MATCH.domain),
        Product(product=CONTAINS('wordpress'), addr=MATCH.addr, port=MATCH.port),
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        OR(
            HostnameIPv4Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
            HostnameIPv6Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
        ),
        NOT(ScanPresent(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port)),
        salience=200
    )
    def need_wordpress_scan_resolved_hostname(self, hostname: str, addr: str, port: int, secure: bool):
        self.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, hostname=hostname, addr=addr, port=port, secure=secure))

    @Rule(
        VirtualHostname(hostname=MATCH.hostname, port=MATCH.port, secure=MATCH.secure),
        Product(product=CONTAINS('wordpress'), hostname=MATCH.hostname, port=MATCH.port),
        NOT(ScanPresent(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port)),
    )
    def need_wordpress_scan_virtual_hostname(self, hostname: str, port: int, secure: bool):
        self.declare(ScanNeeded(category=ToolCategory.wordpress_scanner, hostname=hostname, port=port, secure=secure))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.wordpress_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.wordpress_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def do_not_need_wordpress_scan_by_addr(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port),
        ScanPresent(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port),
    )
    def do_not_need_wordpress_scan_by_hostname(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.wordpress_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.wordpress_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def retract_wordpress_scan_tool_by_addr(self, f1: ToolRecommended):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port),
        ScanPresent(category=ToolCategory.wordpress_scanner, hostname=MATCH.hostname, port=MATCH.port),
    )
    def retract_wordpress_scan_tool_by_hostname(self, f1: ToolRecommended):
        self.retract(f1)

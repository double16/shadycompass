from abc import ABC

from experta import Rule, NOT, MATCH, AS, OR

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, TargetIPv4Address, TargetIPv6Address, \
    VirtualHostname, HostnameIPv4Resolution, HostnameIPv6Resolution, HttpService
from shadycompass.rules.irules import IRules


class HttpSpiderScan(IRules, ABC):
    @Rule(
        AS.f1 << HttpService(addr=MATCH.addr, port=MATCH.port),
        VirtualHostname(hostname=MATCH.hostname, domain=MATCH.domain, port=MATCH.port),
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        OR(
            HostnameIPv4Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
            HostnameIPv6Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
        ),
        NOT(ScanPresent(category=ToolCategory.http_spider, addr=MATCH.addr, port=MATCH.port, hostname=MATCH.hostname)),
    )
    def need_http_spider(self, f1: HttpService, addr, port, hostname):
        self.declare(ScanNeeded(category=ToolCategory.http_spider, secure=f1.is_secure(), addr=addr, port=port,
                                hostname=hostname))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.http_spider, addr=MATCH.addr, port=MATCH.port,
                            hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.http_spider, addr=MATCH.addr, port=MATCH.port, hostname=MATCH.hostname),
    )
    def do_not_need_http_spider(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.http_spider, addr=MATCH.addr, port=MATCH.port,
                                 hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.http_spider, addr=MATCH.addr, port=MATCH.port, hostname=MATCH.hostname),
    )
    def retract__http_spider(self, f1: ToolRecommended):
        self.retract(f1)

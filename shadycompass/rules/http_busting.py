from abc import ABC

from experta import Rule, OR, AS, MATCH, NOT

from shadycompass.facts import HttpService, HttpUrl, HttpBustingNeeded, TargetIPv4Address, TargetIPv6Address, \
    HostnameIPv4Resolution, HostnameIPv6Resolution, VirtualHostname
from shadycompass.rules.irules import IRules

"""
Rules to decide if we need to bust HTTP servers.
"""


class HttpBusting(IRules, ABC):
    @Rule(
        HttpService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        OR(HostnameIPv4Resolution(hostname=MATCH.hostname, addr=MATCH.addr),
           HostnameIPv6Resolution(hostname=MATCH.hostname, addr=MATCH.addr)),
        NOT(VirtualHostname(hostname=MATCH.hostname, port=MATCH.port)),
    )
    def virtualhostname_from_httpservice(self, port, hostname, secure):
        self.declare(VirtualHostname(hostname=hostname, port=port, secure=secure))

    @Rule(
        AS.f1 << HttpService(addr=MATCH.addr, port=MATCH.port),
        VirtualHostname(hostname=MATCH.hostname, domain=MATCH.domain, port=MATCH.port),
        OR(TargetIPv4Address(addr=MATCH.addr), TargetIPv6Address(addr=MATCH.addr)),
        OR(
            HostnameIPv4Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
            HostnameIPv6Resolution(addr=MATCH.addr, hostname=MATCH.hostname | MATCH.domain),
        ),
        NOT(HttpUrl(port=MATCH.port, vhost=MATCH.hostname)),
    )
    def need_http_busting(self, f1: HttpService, addr, port, hostname):
        self.declare(HttpBustingNeeded(secure=f1.is_secure(), addr=addr, port=port, vhost=hostname))

    @Rule(
        AS.f1 << HttpBustingNeeded(secure=MATCH.secure, addr=MATCH.addr, port=MATCH.port, vhost=MATCH.hostname),
        HttpUrl(secure=MATCH.secure, port=MATCH.port, vhost=MATCH.hostname),
    )
    def do_not_need_http_busting(self, f1: HttpBustingNeeded):
        self.retract(f1)

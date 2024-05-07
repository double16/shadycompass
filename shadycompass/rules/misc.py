import ipaddress
from abc import ABC

from experta import Rule, AS, MATCH, OR, NOT, P, AND

from shadycompass import ConfigFact
from shadycompass.config import SECTION_DEFAULT, OPTION_PRODUCTION, OPTION_RATELIMIT
from shadycompass.facts import ProductionTarget, TargetIPv4Address, TargetIPv6Address, RateLimitEnable, ScanNeeded, \
    PublicTarget, WindowsDomain, TargetDomain, TlsCertificate
from shadycompass.rules.irules import IRules

TRUTHY = P(lambda v: str(v).lower() in ['true', 't', '1'])
NOT_TRUTHY = P(lambda v: v is None or str(v).lower() in ['false', 'f', '0'])


def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False  # Invalid IP address


IS_PUBLIC_IP = P(is_public_ip)


class ProductionTargetRules(IRules, ABC):

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=TRUTHY),
        AS.target << TargetIPv4Address(),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False)),
    )
    def production_target_ipv4(self, target: TargetIPv4Address):
        self.declare(ProductionTarget(addr=target.get_addr()))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=TRUTHY),
        AS.target << TargetIPv6Address(),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False)),
    )
    def production_target_ipv6(self, target: TargetIPv6Address):
        self.declare(ProductionTarget(addr=target.get_addr()))

    @Rule(
        AS.f1 << ProductionTarget(addr=MATCH.addr),
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=False),
        salience=100,
    )
    def non_production_target_local(self, f1):
        self.retract(f1)

    @Rule(
        AS.f1 << ProductionTarget(addr=MATCH.addr),
        OR(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, value=NOT_TRUTHY, global0=True),
           NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, global0=True))),
        AND(NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION, global0=False)), NOT(PublicTarget(addr=MATCH.addr)))
    )
    def non_production_target(self, f1):
        self.retract(f1)


class RateLimitRules(IRules, ABC):

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        salience=100,
    )
    def ratelimit_target_local_any(self, ratelimit: str):
        self.declare(RateLimitEnable(addr=ScanNeeded.ANY, request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        AS.target << TargetIPv4Address(addr=MATCH.addr),
        salience=100,
    )
    def ratelimit_target_local_ipv4(self, target: TargetIPv4Address, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=False),
        AS.target << TargetIPv6Address(addr=MATCH.addr),
        salience=100,
    )
    def ratelimit_target_local_ipv6(self, target: TargetIPv6Address, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, value=MATCH.ratelimit, global0=True),
        AS.target << ProductionTarget(addr=MATCH.addr),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT, global0=False)),
    )
    def ratelimit_target_global(self, target: ProductionTarget, ratelimit: str):
        self.declare(RateLimitEnable(addr=target.get_addr(), request_per_second=int(ratelimit)))

    @Rule(
        AS.f1 << RateLimitEnable(addr=MATCH.addr),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_RATELIMIT)),
    )
    def non_ratelimit_target(self, f1):
        self.retract(f1)


class PublicAddrRules(IRules, ABC):

    @Rule(
        OR(TargetIPv4Address(addr=MATCH.addr & IS_PUBLIC_IP), TargetIPv6Address(addr=MATCH.addr & IS_PUBLIC_IP))
    )
    def public_ipv4(self, addr):
        self.declare(PublicTarget(addr=addr))

    @Rule(
        PublicTarget(addr=MATCH.addr),
        NOT(ConfigFact(section=SECTION_DEFAULT, option=OPTION_PRODUCTION)),
    )
    def public_defaults_to_production(self, addr):
        self.declare(ProductionTarget(addr=addr))


class MiscRules(IRules, ABC):
    @Rule(
        WindowsDomain(dns_domain_name=MATCH.target_domain),
        NOT(TargetDomain(domain=MATCH.target_domain))
    )
    def windows_domain_target_domain(self, target_domain: str):
        self.declare(TargetDomain(domain=target_domain))

    @Rule(
        AS.f1 << TlsCertificate()
    )
    def tls_cert_target_domain(self, f1: TlsCertificate):
        if 'localhost' not in f1.get_domain():
            self.declare(TargetDomain(domain=f1.get_domain()))

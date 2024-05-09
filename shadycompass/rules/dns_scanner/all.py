from shadycompass.rules.dns_scanner.dig import DigRules
from shadycompass.rules.dns_scanner.dnsenum import DnsEnumRules
from shadycompass.rules.dns_scanner.dnsrecon import DnsReconRules
from shadycompass.rules.dns_scanner.fierce import FierceRules


class AllRules(
    DigRules,
    DnsEnumRules,
    DnsReconRules,
    FierceRules,
):
    """
    Convenience class to collect all http buster rules.
    """
    pass

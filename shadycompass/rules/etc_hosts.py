from experta import Rule, AS, MATCH

from shadycompass import ToolRecommended
from shadycompass.facts import HostnameIPv4Resolution, TargetIPv4Address, HostnameIPv6Resolution, TargetIPv6Address
from shadycompass.facts.etc_hosts import get_etc_hosts

CATEGORY_HOSTS = 'hosts'


class EtcHostsRules:
    def _recommend(self, addr: str, hostname: str):
        etc_hosts = get_etc_hosts()
        self.declare(
            ToolRecommended(addr=addr, category=CATEGORY_HOSTS, name=f'add `{addr} {hostname}` to {etc_hosts}'))

    @Rule(
        AS.hostname << HostnameIPv4Resolution(addr=MATCH.addr, implied=True),
        AS.ip << TargetIPv4Address(addr=MATCH.addr),
    )
    def add_private_ipv4_address_to_etc_hosts(self, hostname: HostnameIPv4Resolution, ip: TargetIPv4Address):
        if ip.is_private_ip():
            self._recommend(ip.get_addr(), hostname.get_hostname())

    @Rule(
        AS.hostname << HostnameIPv6Resolution(addr=MATCH.addr, implied=True),
        AS.ip << TargetIPv6Address(addr=MATCH.addr),
    )
    def add_private_ipv6_address_to_etc_hosts(self, hostname: HostnameIPv4Resolution, ip: TargetIPv4Address):
        if ip.is_private_ip():
            self._recommend(ip.get_addr(), hostname.get_hostname())

    @Rule(
        HostnameIPv4Resolution(addr=MATCH.addr, implied=False),
        TargetIPv4Address(addr=MATCH.addr),
        AS.f1 << ToolRecommended(addr=MATCH.addr, category=CATEGORY_HOSTS)
    )
    def retract_private_ipv4_address_to_etc_hosts(self, f1):
        self.retract(f1)

    @Rule(
        HostnameIPv6Resolution(addr=MATCH.addr, implied=False),
        TargetIPv6Address(addr=MATCH.addr),
        AS.f1 << ToolRecommended(addr=MATCH.addr, category=CATEGORY_HOSTS)
    )
    def retract_private_ipv6_address_to_etc_hosts(self, f1):
        self.retract(f1)

from base import RulesBase
from shadycompass import ToolRecommended
from shadycompass.facts import HostnameIPv4Resolution, HostnameIPv6Resolution, TargetIPv4Address, TargetIPv6Address
from shadycompass.rules.etc_hosts import CATEGORY_HOSTS
from tests.tests import assertFactIn, assertFactNotIn


class EtcHostsRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_add_private_ipv4(self):
        implied = HostnameIPv4Resolution(hostname='unknown.com', addr='10.11.1.1', implied=True)
        recommend = ToolRecommended(category=CATEGORY_HOSTS, addr='10.11.1.1')
        self.engine.declare(TargetIPv4Address(addr='10.11.1.1'))
        self.engine.declare(implied)
        self.engine.run()
        assertFactIn(recommend, self.engine)
        self.engine.retract(implied)
        self.engine.declare(HostnameIPv4Resolution(hostname='unknown.com', addr='10.11.1.1', implied=False))
        self.engine.run()
        assertFactNotIn(recommend, self.engine)

    def test_add_private_ipv6(self):
        implied = HostnameIPv6Resolution(hostname='unknown.com', addr='fe80::1', implied=True)
        recommend = ToolRecommended(category=CATEGORY_HOSTS, addr='fe80::1')
        self.engine.declare(TargetIPv6Address(addr='fe80::1'))
        self.engine.declare(implied)
        self.engine.run()
        assertFactIn(recommend, self.engine)
        self.engine.retract(implied)
        self.engine.declare(HostnameIPv6Resolution(hostname='unknown.com', addr='fe80::1', implied=False))
        self.engine.run()
        assertFactNotIn(recommend, self.engine)

    def test_public_ipv4(self):
        self.engine.declare(TargetIPv4Address(addr='8.8.8.8'))
        self.engine.declare(HostnameIPv4Resolution(hostname='unknown.com', addr='8.8.8.8', implied=True))
        self.engine.run()
        assertFactNotIn(ToolRecommended(category=CATEGORY_HOSTS, addr='8.8.8.8'), self.engine)

    def test_public_ipv6(self):
        self.engine.declare(TargetIPv6Address(addr='2607:f8b0:4002:c1b::6a'))
        self.engine.declare(HostnameIPv6Resolution(hostname='unknown.com', addr='2607:f8b0:4002:c1b::6a', implied=True))
        self.engine.run()
        assertFactNotIn(ToolRecommended(category=CATEGORY_HOSTS, addr='2607:f8b0:4002:c1b::6a'), self.engine)

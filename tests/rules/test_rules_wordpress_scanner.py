from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, TargetHostname, HostnameIPv4Resolution, \
    VirtualHostname, Product, OSTYPE_WINDOWS, TargetIPv4Address
from tests.tests import assertFactIn, assertFactNotIn


class WordpressScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_wordpress_scan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner), self.engine)

    def test_wordpress_scan_one_target(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(
            VirtualHostname(hostname='blog.shadycompass.test', domain='shadycompass.test', port=80, secure=False))
        self.engine.declare(Product(
            product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS,
            hostname='shadycompass.test', addr='10.1.1.1', port=80))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)
        self.engine.declare(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)

    def test_wordpress_scan_two_virtualhosts(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(
            VirtualHostname(hostname='blog.shadycompass.test', domain='shadycompass.test', port=80, secure=False))
        self.engine.declare(
            VirtualHostname(hostname='www.shadycompass.test', domain='shadycompass.test', port=80, secure=False))
        self.engine.declare(Product(
            product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS,
            hostname='shadycompass.test', addr='10.1.1.1', port=80))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='www.shadycompass.test', secure=False),
            self.engine)
        self.engine.declare(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False))
        self.engine.declare(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.1.1.1', port=80,
            hostname='www.shadycompass.test', secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='www.shadycompass.test', secure=False),
            self.engine)

    def test_wordpress_scan_two_targets(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(
            VirtualHostname(hostname='blog.shadycompass.test', domain='shadycompass.test', port=80, secure=False))
        self.engine.declare(Product(
            product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS,
            hostname='shadycompass.test', addr='10.1.1.1', port=80, secure=False))
        self.engine.declare(TargetHostname(hostname="shadycompass2.test"))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.2'))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass2.test", addr='10.1.1.2'))
        self.engine.declare(
            VirtualHostname(hostname='www.shadycompass2.test', domain='shadycompass2.test', port=443, secure=True))
        self.engine.declare(Product(
            product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS,
            hostname='shadycompass2.test', addr='10.1.1.2', port=443, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.2', port=443,
            hostname='www.shadycompass2.test', secure=True),
            self.engine)
        self.engine.declare(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False))
        self.engine.declare(ScanPresent(
            category=ToolCategory.wordpress_scanner, name='wpscan', addr='10.1.1.2', port=443,
            hostname='www.shadycompass2.test', secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80,
            hostname='blog.shadycompass.test', secure=False),
            self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.2', port=443,
            hostname='www.shadycompass2.test', secure=True),
            self.engine)

    def test_wordpress_scan_no_hostname(self):
        self.engine.declare(TargetIPv4Address(addr="10.1.1.1"))
        self.engine.declare(Product(
            product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS, addr='10.1.1.1', port=80, secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.wordpress_scanner, addr='10.1.1.1', port=80, secure=False),
            self.engine)

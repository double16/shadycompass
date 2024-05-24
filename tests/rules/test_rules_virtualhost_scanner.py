from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, HttpService, TargetHostname, HostnameIPv4Resolution
from tests.tests import assertFactIn, assertFactNotIn


class VirtualHostScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_virtualhost_scan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner), self.engine)

    def test_virtualhost_scan_one_target(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(HttpService(addr='10.1.1.1', port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False, url='http://shadycompass.test:80'),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True, url='https://shadycompass.test:443'),
            self.engine)

    def test_virtualhost_scan_two_target(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(TargetHostname(hostname="shadycompass2.test"))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass2.test", addr='10.1.1.2'))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True))
        self.engine.declare(HttpService(addr='10.1.1.2', hostname="shadycompass2.test", port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.2', hostname="shadycompass2.test", port=443, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False, url='http://shadycompass.test:80'),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True, url='https://shadycompass.test:443'),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.2', hostname="shadycompass2.test", port=80, secure=False, url='http://shadycompass2.test:80'),
            self.engine)
        assertFactIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.2', hostname="shadycompass2.test", port=443, secure=True,
            url='https://shadycompass2.test:443'),
            self.engine)

    def test_virtualhost_scan_present1(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True))
        self.engine.declare(ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', addr='10.1.1.1',
                                        hostname="shadycompass.test", port=80))
        self.engine.declare(ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', addr='10.1.1.1',
                                        hostname="shadycompass.test", port=443))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False),
            self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True),
            self.engine)

    def test_virtualhost_scan_present2(self):
        self.engine.declare(TargetHostname(hostname="shadycompass.test"))
        self.engine.declare(HostnameIPv4Resolution(hostname="shadycompass.test", addr='10.1.1.1'))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', addr='10.1.1.1',
                                        hostname="shadycompass.test", port=80))
        self.engine.declare(ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', addr='10.1.1.1',
                                        hostname="shadycompass.test", port=443))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=80, secure=False),
            self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', hostname="shadycompass.test", port=443, secure=True),
            self.engine)

    def test_virtualhost_scan_no_hostname(self):
        self.engine.declare(HttpService(addr='10.1.1.1', port=80, secure=False))
        self.engine.declare(HttpService(addr='10.1.1.1', port=443, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', port=80, secure=False),
            self.engine)
        assertFactNotIn(ScanNeeded(
            category=ToolCategory.virtualhost_scanner,
            addr='10.1.1.1', port=443, secure=True),
            self.engine)

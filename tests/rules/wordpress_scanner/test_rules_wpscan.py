from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, SECTION_TOOLS, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT
from shadycompass.facts import ScanNeeded, TargetIPv4Address, ScanPresent, VirtualHostname, Product, \
    OSTYPE_WINDOWS
from shadycompass.rules.wordpress_scanner.wpscan import WpscanRules
from tests.rules.base import RulesBase
from tests.tests import assertFactNotIn, assertFactIn


class WpscanRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_wpscan_hostname(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.wordpress_scanner, WpscanRules.wpscan_name, True)
        self.engine.declare(
            VirtualHostname(hostname='blog.shadycompass.test', domain='shadycompass.test', port=80, secure=False))
        self.engine.declare(
            Product(product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS, addr='10.129.229.189', port=80))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189', port=80,
                       hostname='blog.shadycompass.test', secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name,
            command_line=[
                '--url', 'http://blog.shadycompass.test:80',
                '-o', 'wpscan-80-blog.shadycompass.test.json',
            ],
            addr='10.129.229.189', port=80, hostname='blog.shadycompass.test',
        ), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.wordpress_scanner, name=WpscanRules.wpscan_name,
                        addr='10.129.229.189', port=80, hostname='blog.shadycompass.test', secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189',
                                   hostname='blog.shadycompass.test'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.wordpress_scanner, name=WpscanRules.wpscan_name),
                        self.engine)

    def test_wpscan_address(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.wordpress_scanner, WpscanRules.wpscan_name, True)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            Product(product='wordpress', version='5.4', ostype=OSTYPE_WINDOWS, addr='10.129.229.189', port=80))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189', port=80, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name,
            command_line=[
                '--url', 'http://10.129.229.189:80',
                '-o', 'wpscan-80-10.129.229.189.json',
            ],
            addr='10.129.229.189', port=80,
        ), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.wordpress_scanner, name=WpscanRules.wpscan_name,
                        addr='10.129.229.189', port=80, secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.wordpress_scanner, name=WpscanRules.wpscan_name),
                        self.engine)

    def test_wpscan_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.wordpress_scanner, WpscanRules.wpscan_name, False)
        self.engine.config_set(SECTION_OPTIONS, WpscanRules.wpscan_name, '-v', False)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189', port=80,
                       hostname='blog.shadycompass.test', secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name,
            command_line=[
                '-v',
                '--url', 'http://blog.shadycompass.test:80',
                '-o', 'wpscan-80-blog.shadycompass.test.json',
            ],
            addr='10.129.229.189', port=80, hostname='blog.shadycompass.test',
        ), self.engine)

    def test_wpscan_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.wordpress_scanner, WpscanRules.wpscan_name, True)
        self.engine.config_set(SECTION_OPTIONS, WpscanRules.wpscan_name, '-v', True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189', port=80,
                       hostname='blog.shadycompass.test', secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name,
            command_line=[
                '-v',
                '--url', 'http://blog.shadycompass.test:80',
                '-o', 'wpscan-80-blog.shadycompass.test.json',
            ],
            addr='10.129.229.189', port=80, hostname='blog.shadycompass.test',
        ), self.engine)

    def test_wpscan_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.wordpress_scanner, WpscanRules.wpscan_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.wordpress_scanner, addr='10.129.229.189', port=80, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name,
            command_line=[
                '--throttle', '12000',
                '--url', 'http://10.129.229.189:80',
                '-o', 'wpscan-80-10.129.229.189.json',
            ],
            addr='10.129.229.189', port=80,
        ), self.engine)


class WpscanRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_wpscan(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.wordpress_scanner,
            name=WpscanRules.wpscan_name
        ), self.engine)

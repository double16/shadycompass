from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, PreferredTool, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT, \
    OPTION_PRODUCTION
from shadycompass.facts import ScanNeeded, TargetIPv4Address, ScanPresent, PopService, ImapService, SmtpService, \
    Username
from shadycompass.rules.port_scanner.nmap import NmapRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class NmapTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)
        self.nmap_all_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '$IP'],
        )
        self.nmap_top_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml', '$IP'],
        )
        self.rustscan_all_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['-a', '$IP', '--', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml'],
        )
        self.rustscan_top_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['--top', '$IP', '--', '-sV', '-sC', '-oN', 'nmap-tcp-1000.txt', '-oX', 'nmap-tcp-1000.xml'],
        )

    def test_no_services_recommend_nmap_rustscan(self):
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactIn(self.nmap_all_fact, self.engine)
        assertFactIn(self.nmap_top_fact, self.engine)
        assertFactIn(self.rustscan_all_fact, self.engine)
        assertFactIn(self.rustscan_top_fact, self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(self.nmap_all_fact, self.engine)
        assertFactNotIn(self.nmap_top_fact, self.engine)
        assertFactNotIn(self.rustscan_all_fact, self.engine)
        assertFactNotIn(self.rustscan_top_fact, self.engine)

    def test_no_services_recommend_nmap(self):
        self.engine.declare(PreferredTool(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactIn(self.nmap_all_fact, self.engine)
        assertFactIn(self.nmap_top_fact, self.engine)
        assertFactNotIn(self.rustscan_all_fact, self.engine)
        assertFactNotIn(self.rustscan_top_fact, self.engine)

    def test_no_services_recommend_rustscan(self):
        self.engine.declare(PreferredTool(category=ToolCategory.port_scanner, name=NmapRules.rustscan_tool_name))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactNotIn(self.nmap_all_fact, self.engine)
        assertFactNotIn(self.nmap_top_fact, self.engine)
        assertFactIn(self.rustscan_all_fact, self.engine)
        assertFactIn(self.rustscan_top_fact, self.engine)

    def test_no_services_recommend_nmap_rustscan_options(self):
        self.engine.reset()
        self.engine.config_set(SECTION_OPTIONS, NmapRules.nmap_tool_name, '--nmap-option', True)
        self.engine.config_set(SECTION_OPTIONS, NmapRules.rustscan_tool_name, '--rustscan-option', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '--nmap-option',
                          '$IP'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
                          '--nmap-option', '$IP'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['-a', '$IP', '--', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml',
                          '--rustscan-option'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['--top', '$IP', '--', '-sV', '-sC', '-oN', 'nmap-tcp-1000.txt', '-oX', 'nmap-tcp-1000.xml',
                          '--rustscan-option'],
        ), self.engine)

    def test_nmap_ratelimit_any(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '--max-rate', '5',
                          '$IP'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
                          '--max-rate', '5', '$IP'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '$IP'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '5', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
                          '$IP'],
        ), self.engine)

    def test_nmap_ratelimit_one(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.1'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-all.txt', '-oX', 'nmap-10.1.1.1-tcp-all.xml', '--max-rate', '5',
                          '10.1.1.1'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-100.txt', '-oX', 'nmap-10.1.1.1-tcp-100.xml',
                          '--max-rate', '5', '10.1.1.1'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-all.txt', '-oX', 'nmap-10.1.1.1-tcp-all.xml', '10.1.1.1'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '5', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-100.txt', '-oX', 'nmap-10.1.1.1-tcp-100.xml',
                          '10.1.1.1'],
        ), self.engine)

    def test_rustscan_ratelimit_global(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactIn(self.rustscan_all_fact, self.engine)
        assertFactIn(self.rustscan_top_fact, self.engine)

    def test_rustscan_ratelimit_local(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner), self.engine)
        assertFactNotIn(self.rustscan_all_fact, self.engine)
        assertFactNotIn(self.rustscan_top_fact, self.engine)

    def test_rustscan_one(self):
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.port_scanner, addr='10.1.1.1'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['-a', '10.1.1.1', '--', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-all.txt', '-oX', 'nmap-10.1.1.1-tcp-all.xml'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['--top', '10.1.1.1', '--', '-sV', '-sC', '-oN', 'nmap-10.1.1.1-tcp-1000.txt', '-oX', 'nmap-10.1.1.1-tcp-1000.xml'],
        ), self.engine)


class NmapPopScannerNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml'], methodName)

    def test_nmap_pop_scanner_recommended(self):
        self.engine.declare(PopService(addr='10.129.229.189', port=110, secure=False))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.129.229.189', port=110), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.pop_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=110,
            command_line=[
                '--script', 'pop3-capabilities or pop3-ntlm-info', '-sV',
                '-p110',
                '-oN', 'nmap-10.129.229.189-110-pop.txt',
                '-oX', 'nmap-10.129.229.189-110-pop.xml',
                '10.129.229.189'
            ],
        ), self.engine)

    def test_nmap_pop_scanner_retract(self):
        self.engine.declare(PopService(addr='10.129.229.189', port=110, secure=False))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.129.229.189', port=110), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.pop_scanner, name=NmapRules.nmap_tool_name,
                                        addr='10.129.229.189', port=110))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.pop_scanner, addr='10.129.229.189', port=110), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.pop_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=110,
        ), self.engine)


class NmapPopScannerNotNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml', 'tests/fixtures/nmap/pop/nmap-pop.xml'], methodName)

    def test_nmap_pop_scanner_not_recommended(self):
        assertFactIn(ScanPresent(category=ToolCategory.pop_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=110), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.pop_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=110,
        ), self.engine)


class NmapImapScannerNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml'], methodName)

    def test_nmap_imap_scanner_recommended(self):
        self.engine.declare(ImapService(addr='10.129.229.189', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.129.229.189', port=993, secure=True))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=143, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=993, secure=True),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=143,
            command_line=[
                '--script', 'imap-capabilities or imap-ntlm-info', '-sV',
                '-p143',
                '-oN', 'nmap-10.129.229.189-143-imap.txt',
                '-oX', 'nmap-10.129.229.189-143-imap.xml',
                '10.129.229.189'
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=993,
            command_line=[
                '--script', 'imap-capabilities or imap-ntlm-info', '-sV',
                '-p993',
                '-oN', 'nmap-10.129.229.189-993-imap.txt',
                '-oX', 'nmap-10.129.229.189-993-imap.xml',
                '10.129.229.189'
            ],
        ), self.engine)

    def test_nmap_imap_scanner_retract(self):
        self.engine.declare(ImapService(addr='10.129.229.189', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.129.229.189', port=993, secure=True))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=143, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=993, secure=True),
                     self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name=NmapRules.nmap_tool_name,
                                        addr='10.129.229.189', port=143))
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name=NmapRules.nmap_tool_name,
                                        addr='10.129.229.189', port=993))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=143), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.129.229.189', port=993), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=143,
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=993,
        ), self.engine)


class NmapImapScannerNotNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml', 'tests/fixtures/nmap/imap/nmap-imap.xml'],
                         methodName)

    def test_nmap_imap_scanner_not_recommended(self):
        assertFactIn(ScanPresent(category=ToolCategory.imap_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=143), self.engine)
        assertFactIn(ScanPresent(category=ToolCategory.imap_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=993), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=143,
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.imap_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=993,
        ), self.engine)


class NmapSmtpScannerNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml'], methodName)

    def test_nmap_smtp_scanner_recommended(self):
        self.engine.declare(SmtpService(addr='10.129.229.189', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.129.229.189', port=587, secure=True))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=587, secure=True),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=25,
            command_line=[
                '--script', 'smtp* not brute', '-sV',
                '-p25',
                '-oN', 'nmap-10.129.229.189-25-smtp.txt',
                '-oX', 'nmap-10.129.229.189-25-smtp.xml',
                '10.129.229.189'
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=587,
            command_line=[
                '--script', 'smtp* not brute', '-sV',
                '-p587',
                '-oN', 'nmap-10.129.229.189-587-smtp.txt',
                '-oX', 'nmap-10.129.229.189-587-smtp.xml',
                '10.129.229.189'
            ],
        ), self.engine)

    def test_nmap_smtp_scanner_retract(self):
        self.engine.declare(SmtpService(addr='10.129.229.189', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.129.229.189', port=587, secure=True))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=587, secure=True),
                     self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name=NmapRules.nmap_tool_name,
                                        addr='10.129.229.189', port=25))
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name=NmapRules.nmap_tool_name,
                                        addr='10.129.229.189', port=587))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=587), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=25,
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=587,
        ), self.engine)


class NmapSmtpScannerNotNeededTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['tests/fixtures/nmap/all/open-ports.xml', 'tests/fixtures/nmap/smtp/nmap-smtp.xml'],
                         methodName)

    def test_nmap_smtp_scanner_not_recommended(self):
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=25), self.engine)
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=465), self.engine)
        assertFactIn(ScanPresent(category=ToolCategory.smtp_scanner, name=NmapRules.nmap_tool_name,
                                 addr='10.129.229.189', port=587), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=25,
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=465,
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=NmapRules.nmap_tool_name,
            addr='10.129.229.189',
            port=587,
        ), self.engine)
        assertFactNotIn(Username(username='RCPT'), self.engine)
        assertFactIn(Username(username='root'), self.engine)
        assertFactIn(Username(username='user1'), self.engine)
        assertFactIn(Username(username='user2'), self.engine)
        assertFactIn(Username(), self.engine, times=3)

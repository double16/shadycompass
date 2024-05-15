from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, SECTION_TOOLS, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT
from shadycompass.facts import ScanNeeded, TargetDomain, TargetIPv4Address, ScanPresent
from shadycompass.rules.smtp_scanner.smtp_user_enum import SmtpUserEnumRules
from tests.rules.base import RulesBase
from tests.tests import assertFactNotIn, assertFactIn


class SmtpUserEnumRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_smtp_user_enum(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25,
                                        name=SmtpUserEnumRules.smtp_user_enum_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.smtp_scanner, name=SmtpUserEnumRules.smtp_user_enum_name),
                        self.engine)

    def test_smtp_user_enum_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, False)
        self.engine.config_set(SECTION_OPTIONS, SmtpUserEnumRules.smtp_user_enum_name, '-v', False)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-v',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)

    def test_smtp_user_enum_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, True)
        self.engine.config_set(SECTION_OPTIONS, SmtpUserEnumRules.smtp_user_enum_name, '-v', True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-v',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)

    def test_smtp_user_enum_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.declare(TargetDomain(domain='shadycompass.test'))
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-D', 'shadycompass.test',
                '-f', 'user@shadycompass.test',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25-shadycompass.test.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-D', 'shadycompass2.test',
                '-f', 'user@shadycompass2.test',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25-shadycompass2.test.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)

    def test_smtp_user_enum_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-m', '1',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)

    def test_smtp_user_enum_domains_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smtp_scanner, SmtpUserEnumRules.smtp_user_enum_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.129.229.189', port=25, secure=False))
        self.engine.declare(TargetDomain(domain='shadycompass.test'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name,
            command_line=[
                '-M', 'VRFY',
                '-U', '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '-m', '1',
                '-D', 'shadycompass.test',
                '-f', 'user@shadycompass.test',
                '-t', '10.129.229.189', '-p', '25',
                '>smtp-user-enum-10.129.229.189-25-shadycompass.test.txt',
            ],
            addr='10.129.229.189', port=25,
        ), self.engine)


class SmtpUserEnumRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_smtp_user_enum(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smtp_scanner,
            name=SmtpUserEnumRules.smtp_user_enum_name
        ), self.engine)

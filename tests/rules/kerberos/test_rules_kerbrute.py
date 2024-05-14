from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT
from shadycompass.facts import ScanNeeded, WindowsDomain, TargetIPv4Address, Kerberos5SecTcpService
from shadycompass.rules.kerberos.kerbrute import KerbruteRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class KerbruteRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_asrep_roaster(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '-d', 'SHADYCOMPASS',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
        ), self.engine)

    def test_asrep_roaster_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, KerbruteRules.kerbrute_tool_name, '-v', False)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189', port=88, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '-d', 'SHADYCOMPASS',
                'userenum',
                '-v',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)

    def test_asrep_roaster_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, KerbruteRules.kerbrute_tool_name, '-v', True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189', port=88, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '-d', 'SHADYCOMPASS',
                'userenum',
                '-v',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)

    def test_asrep_roaster_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.declare(
            ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189', port=88, secure=False))
        self.engine.declare(WindowsDomain(netbios_domain_name='SHADYCOMPASS2'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '-d', 'SHADYCOMPASS',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '-d', 'SHADYCOMPASS2',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS2.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)

    def test_asrep_roaster_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189', port=88, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '--delay', '12000', '-d', 'SHADYCOMPASS',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)

    def test_asrep_roaster_domains_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.declare(TargetIPv4Address(addr='10.129.229.189'))
        self.engine.declare(
            ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.129.229.189', port=88, secure=False))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.129.229.189', '--delay', '12000', '-d', 'SHADYCOMPASS',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.129.229.189-SHADYCOMPASS.txt'
            ],
            addr='10.129.229.189', port=88,
        ), self.engine)


class KerbruteRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_asrep_roaster(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name
        ), self.engine)

    def test_asrep_roaster_no_domain(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.asrep_roaster, KerbruteRules.kerbrute_tool_name, True)
        self.engine.declare(Kerberos5SecTcpService(addr='10.1.1.1', port=88))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.1'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.asrep_roaster,
            name=KerbruteRules.kerbrute_tool_name,
            command_line=[
                '--safe', '--dc', '10.1.1.1',
                'userenum',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                '>kerbrute-userenum-10.1.1.1.txt'
            ],
        ), self.engine)

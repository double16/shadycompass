from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION
from shadycompass.facts import ScanNeeded, ScanPresent, TargetDomain
from shadycompass.rules.dns_scanner.fierce import FierceRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class FierceTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_fierce(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--domain', 'shadycompass.test',
                '>fierce-10.129.229.189-53-shadycompass.test.txt',
            ],
        ), self.engine)

    def test_fierce_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', False)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--delay', '12',
                '--domain', 'shadycompass.test',
                '>fierce-10.129.229.189-53-shadycompass.test.txt',
            ],
        ), self.engine)

    def test_fierce_two_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, True)
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--domain', 'shadycompass.test',
                '>fierce-10.129.229.189-53-shadycompass.test.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--domain', 'shadycompass2.test',
                '>fierce-10.129.229.189-53-shadycompass2.test.txt',
            ],
        ), self.engine)

    def test_fierce_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, FierceRules.fierce_tool_name, '--wide', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--wide',
                '--domain', 'shadycompass.test',
                '>fierce-10.129.229.189-53-shadycompass.test.txt',
            ],
        ), self.engine)

    def test_fierce_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, FierceRules.fierce_tool_name, '--wide', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
            command_line=[
                '--dns-servers', '10.129.229.189',
                '--wide',
                '--domain', 'shadycompass.test',
                '>fierce-10.129.229.189-53-shadycompass.test.txt',
            ],
        ), self.engine)

    def test_fierce_retract(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, FierceRules.fierce_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.dns_scanner, name=FierceRules.fierce_tool_name, addr='10.129.229.189',
                        port=53))
        self.engine.run()
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=FierceRules.fierce_tool_name,
        ), self.engine)

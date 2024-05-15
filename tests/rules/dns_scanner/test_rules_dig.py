from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.facts import ScanNeeded, ScanPresent, TargetDomain
from shadycompass.rules.dns_scanner.dig import DigRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class DigTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dig(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DigRules.dig_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'any', '@10.129.229.189', '-p', '53', 'shadycompass.test', '>dig-any-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'axfr', '@10.129.229.189', '-p', '53', 'shadycompass.test', '>dig-axfr-10.129.229.189-53.txt',
            ],
        ), self.engine)
        self.engine.declare(
            ScanPresent(category=ToolCategory.dns_scanner, addr='10.129.229.189', port=53, name=DigRules.dig_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.dns_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.dns_scanner, name=DigRules.dig_tool_name), self.engine)

    def test_dig_two_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DigRules.dig_tool_name, True)
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'any', '@10.129.229.189', '-p', '53', 'shadycompass.test', '>dig-any-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'axfr', '@10.129.229.189', '-p', '53', 'shadycompass.test', '>dig-axfr-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'any', '@10.129.229.189', '-p', '53', 'shadycompass2.test', '>dig-any-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'axfr', '@10.129.229.189', '-p', '53', 'shadycompass2.test', '>dig-axfr-10.129.229.189-53.txt',
            ],
        ), self.engine)

    def test_dig_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DigRules.dig_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, DigRules.dig_tool_name, '+comments', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'any', '@10.129.229.189', '-p', '53', '+comments', 'shadycompass.test', '>dig-any-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'axfr', '@10.129.229.189', '-p', '53', '+comments', 'shadycompass.test', '>dig-axfr-10.129.229.189-53.txt',
            ],
        ), self.engine)

    def test_dig_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DigRules.dig_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, DigRules.dig_tool_name, '+comments', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'any', '@10.129.229.189', '-p', '53', '+comments', 'shadycompass.test', '>dig-any-10.129.229.189-53.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
            command_line=[
                'axfr', '@10.129.229.189', '-p', '53', '+comments', 'shadycompass.test', '>dig-axfr-10.129.229.189-53.txt',
            ],
        ), self.engine)

    def test_dig_retract(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.dns_scanner, DigRules.dig_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.dns_scanner), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.dns_scanner, name=DigRules.dig_tool_name, addr='10.129.229.189', port=53))
        self.engine.run()
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.dns_scanner,
            name=DigRules.dig_tool_name,
        ), self.engine)

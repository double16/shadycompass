from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, PreferredTool, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT, \
    OPTION_PRODUCTION
from shadycompass.facts import ScanNeeded, TargetIPv4Address
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
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '--max-rate', '5',
                          '10.1.1.1'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
                          '--max-rate', '5', '10.1.1.1'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '10.1.1.1'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '5', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
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

from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, PreferredTool
from shadycompass.facts import PortScanNeeded
from shadycompass.rules.port_scanner.nmap import NmapRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class NmapTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)
        self.nmap_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'tcp-all.txt', '-oX', 'tcp-all.xml', '$IP'],
        )
        self.rustscan_fact = ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.rustscan_tool_name,
            command_line=['-a', '$IP', '--', '-sV', '-sC', '-oN', 'tcp-all.txt', '-oX', 'tcp-all.xml'],
        )

    def test_no_services_recommend_nmap_rustscan(self):
        assertFactIn(PortScanNeeded(), self.engine)
        assertFactIn(self.nmap_fact, self.engine)
        assertFactIn(self.rustscan_fact, self.engine)

    def test_no_services_recommend_nmap(self):
        self.engine.declare(PreferredTool(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name))
        self.engine.run()
        assertFactIn(PortScanNeeded(), self.engine)
        assertFactIn(self.nmap_fact, self.engine)
        assertFactNotIn(self.rustscan_fact, self.engine)

    def test_no_services_recommend_rustscan(self):
        self.engine.declare(PreferredTool(category=ToolCategory.port_scanner, name=NmapRules.rustscan_tool_name))
        self.engine.run()
        assertFactIn(PortScanNeeded(), self.engine)
        assertFactNotIn(self.nmap_fact, self.engine)
        assertFactIn(self.rustscan_fact, self.engine)

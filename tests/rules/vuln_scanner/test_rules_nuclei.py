from shadycompass import ToolRecommended
from shadycompass.config import ToolCategory, PreferredTool, SECTION_OPTIONS
from shadycompass.facts import VulnScanNeeded, VulnScanPresent, TargetIPv4Address
from shadycompass.rules.vuln_scanner.nuclei import NucleiRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class NucleiTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)
        self.nuclei_fact_any = ToolRecommended(
            category=ToolCategory.vuln_scanner,
            name=NucleiRules.nuclei_tool_name,
            command_line=['-target', '$IP', '-json-export', 'nuclei-$IP.json'],
            addr=VulnScanNeeded.ANY
        )
        self.nuclei_fact_one = ToolRecommended(
            category=ToolCategory.vuln_scanner,
            name=NucleiRules.nuclei_tool_name,
            command_line=['-target', '10.1.1.1', '-json-export', 'nuclei-10.1.1.1.json'],
            addr='10.1.1.1'
        )

    def test_no_scan_recommend_nuclei(self):
        self.engine.declare(PreferredTool(category=ToolCategory.vuln_scanner, name=NucleiRules.nuclei_tool_name))
        self.engine.run()
        assertFactIn(VulnScanNeeded(), self.engine)
        assertFactIn(self.nuclei_fact_any, self.engine)

    def test_found_scan_recommend_nuclei(self):
        self.engine.declare(PreferredTool(category=ToolCategory.vuln_scanner, name=NucleiRules.nuclei_tool_name))
        self.engine.declare(TargetIPv4Address(addr='10.1.1.1'))
        self.engine.declare(VulnScanPresent(name=NucleiRules.nuclei_tool_name, addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(VulnScanNeeded(), self.engine)
        assertFactNotIn(self.nuclei_fact_one, self.engine)

    def test_no_scan_recommend_nuclei_options(self):
        self.engine.reset()
        self.engine.declare(PreferredTool(category=ToolCategory.vuln_scanner, name=NucleiRules.nuclei_tool_name))
        self.engine.config_set(SECTION_OPTIONS, NucleiRules.nuclei_tool_name, '--nuclei-option', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.vuln_scanner,
            name=NucleiRules.nuclei_tool_name,
            command_line=['-target', '$IP', '-json-export', 'nuclei-$IP.json', '--nuclei-option'],
            addr=VulnScanNeeded.ANY
        ), self.engine)

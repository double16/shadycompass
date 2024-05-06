from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.facts import ScanNeeded
from shadycompass.rules.smb_scanner.enum4linuxng import Enum4LinuxNgRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class Enum4LinuxNgRulesTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_enum4linux_ng(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smb_scanner, Enum4LinuxNgRules.enum4linux_ng_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.129.229.189'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            command_line=['-oJ', "enum4linuxng-10.129.229.189", '-A', '10.129.229.189'],
        ), self.engine)

    def test_enum4linux_ng_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smb_scanner, Enum4LinuxNgRules.enum4linux_ng_tool_name,
                               False)
        self.engine.config_set(SECTION_OPTIONS, Enum4LinuxNgRules.enum4linux_ng_tool_name, '-d', False)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.129.229.189'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            command_line=['-oJ', "enum4linuxng-10.129.229.189", '-A', '-d', '10.129.229.189'],
        ), self.engine)

    def test_enum4linux_ng_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.smb_scanner, Enum4LinuxNgRules.enum4linux_ng_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, Enum4LinuxNgRules.enum4linux_ng_tool_name, '-d', True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.129.229.189'), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name,
            command_line=['-oJ', "enum4linuxng-10.129.229.189", '-A', '-d', '10.129.229.189'],
        ), self.engine)


class Enum4LinuxNgRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_enum4linux_ng(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.smb_scanner,
            name=Enum4LinuxNgRules.enum4linux_ng_tool_name
        ), self.engine)

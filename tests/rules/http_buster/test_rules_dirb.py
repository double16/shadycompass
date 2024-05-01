from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.rules.http_buster.dirb import DirbRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn


class DirbTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dirb(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value=DirbRules.dirb_tool_name, global0=True))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt'],
        ), self.engine)

    def test_dirb_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, DirbRules.dirb_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, DirbRules.dirb_tool_name, '-r', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt', '-r'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt', '-r'],
        ), self.engine)

    def test_dirb_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, DirbRules.dirb_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, DirbRules.dirb_tool_name, '-r', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt', '-r'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt', '-r'],
        ), self.engine)

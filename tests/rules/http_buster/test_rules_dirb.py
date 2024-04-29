from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended
from shadycompass.rules.http_buster.dirb import DirbRules
from tests.tests import assertFactIn
from tests.rules.base import RulesBase


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

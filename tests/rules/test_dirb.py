from base import RulesBase
from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended
from tests.tests import assertFactIn


class DirbTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dirb(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='dirb', global0=True))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name='dirb',
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name='dirb',
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt'],
        ), self.engine)

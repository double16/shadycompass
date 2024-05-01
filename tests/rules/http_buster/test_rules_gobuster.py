from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.rules.http_buster.gobuster import GoBusterRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn


class GobusterTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_gobuster(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, GoBusterRules.gobuster_tool_name, True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-8080-hospital.htb.txt",
                '-u', 'http://hospital.htb:8080'
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-443-hospital.htb.txt",
                '-u', 'https://hospital.htb:443'
            ],
        ), self.engine)

    def test_gobuster_options(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, GoBusterRules.gobuster_tool_name, '--retry', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-8080-hospital.htb.txt",
                '-u', 'http://hospital.htb:8080', '--retry'
            ],
        ), self.engine)

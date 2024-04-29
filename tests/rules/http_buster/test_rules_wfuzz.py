from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended
from shadycompass.rules.http_buster.wfuzz import WfuzzRules
from tests.tests import assertFactIn
from tests.rules.base import RulesBase


class WfuzzTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_wfuzz(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value=WfuzzRules.wfuzz_tool_name, global0=True))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', '/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt',
                '--hc', '404',
                '-f', 'wfuzz-8080-hospital.htb.json,json',
                'http://hospital.htb:8080/FUZZ',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', '/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt',
                '--hc', '404',
                '-f', 'wfuzz-443-hospital.htb.json,json',
                'https://hospital.htb:443/FUZZ',
            ],
        ), self.engine)

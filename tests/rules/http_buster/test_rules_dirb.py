from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION
from shadycompass.rules.http_buster.dirb import DirbRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class DirbTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_dirb(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, DirbRules.dirb_tool_name, True)
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

    def test_dirb_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, DirbRules.dirb_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt', '-z', '12000'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt', '-z', '12000'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['http://hospital.htb:8080', '-o', 'dirb-8080-hospital.htb.txt'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=DirbRules.dirb_tool_name,
            command_line=['https://hospital.htb:443', '-o', 'dirb-443-hospital.htb.txt'],
        ), self.engine)

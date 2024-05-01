from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.rules.http_buster.feroxbuster import FeroxBusterRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn


class FeroxBusterTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_feroxbuster(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, FeroxBusterRules.feroxbuster_tool_name, True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://hospital.htb:8080',
                          '-o', "feroxbuster-8080-hospital.htb.txt",
                          '--scan-limit', '4', '--insecure'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'https://hospital.htb:443',
                          '-o', "feroxbuster-443-hospital.htb.txt",
                          '--scan-limit', '4', '--insecure'],
        ), self.engine)

    def test_feroxbuster_options(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, FeroxBusterRules.feroxbuster_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, FeroxBusterRules.feroxbuster_tool_name, '--scan-limit 53', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://hospital.htb:8080',
                          '-o', "feroxbuster-8080-hospital.htb.txt",
                          '--scan-limit', '53', '--insecure'],
        ), self.engine)

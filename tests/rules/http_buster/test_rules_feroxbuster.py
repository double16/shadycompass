from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended
from tests.tests import assertFactIn
from tests.rules.base import RulesBase


class FeroxBusterTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_feroxbuster(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=True))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name='feroxbuster',
            command_line=['-u', 'http://hospital.htb:8080', '--random-agent', '--extract-links',
                          '-o', "feroxbuster-8080-hospital.htb.txt", '--thorough',
                          '--scan-limit', '6', '--insecure'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name='feroxbuster',
            command_line=['-u', 'https://hospital.htb:443', '--random-agent', '--extract-links',
                          '-o', "feroxbuster-443-hospital.htb.txt", '--thorough',
                          '--scan-limit', '6', '--insecure'],
        ), self.engine)

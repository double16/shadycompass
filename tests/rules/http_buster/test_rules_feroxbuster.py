from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION
from shadycompass.rules.http_buster.feroxbuster import FeroxBusterRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class FeroxBusterTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_feroxbuster(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, FeroxBusterRules.feroxbuster_tool_name, True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-o', "feroxbuster-8080-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '4'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-o', "feroxbuster-443-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '4'],
        ), self.engine)

    def test_feroxbuster_options(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, FeroxBusterRules.feroxbuster_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, FeroxBusterRules.feroxbuster_tool_name, '--scan-limit 53', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-o', "feroxbuster-8080-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '53'],
        ), self.engine)

    def test_feroxbuster_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, FeroxBusterRules.feroxbuster_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-o', "feroxbuster-8080-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '1', '--rate-limit', '5'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-o', "feroxbuster-443-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '1', '--rate-limit', '5'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-o', "feroxbuster-8080-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '4'],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=FeroxBusterRules.feroxbuster_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-o', "feroxbuster-443-shadycompass.test.txt", '--insecure',
                          '--scan-limit', '4'],
        ), self.engine)

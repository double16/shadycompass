from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_DEFAULT, OPTION_RATELIMIT, OPTION_PRODUCTION, \
    SECTION_OPTIONS
from shadycompass.facts import PublicTarget
from shadycompass.rules.http_spider.gospider import GospiderRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn


class GospiderRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_spider, GospiderRules.gospider_tool_name, True)

    def test_gospider_private(self):
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '3',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '3',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)

    def test_gospider_private_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '3',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '3',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)

    def test_gospider_private_options(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_OPTIONS, GospiderRules.gospider_tool_name, '--depth 4', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '4',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '4',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)

    def test_gospider_private_ratelimit_options(self):
        self.engine.config_set(SECTION_OPTIONS, GospiderRules.gospider_tool_name, '--depth 4', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '4',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--depth', '4',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)

    def test_gospider_public(self):
        self.engine.declare(PublicTarget(addr='10.129.229.189'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--include-other-source',
                          '--depth', '3',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--include-other-source',
                          '--depth', '3',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '4'],
        ), self.engine)

    def test_gospider_public_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.declare(PublicTarget(addr='10.129.229.189'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'http://shadycompass.test:8080',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--include-other-source',
                          '--depth', '3',
                          '-o', "gospider-8080-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=GospiderRules.gospider_tool_name,
            command_line=['--site', 'https://shadycompass.test:443',
                          '--user-agent', 'web',
                          '--js', '--sitemap', '--robots',
                          '--include-other-source',
                          '--depth', '3',
                          '-o', "gospider-443-shadycompass.test", '--json',
                          '--concurrent', '1', '--delay', '2'],
        ), self.engine)

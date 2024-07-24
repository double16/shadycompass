from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_DEFAULT, OPTION_RATELIMIT, OPTION_PRODUCTION, \
    SECTION_OPTIONS
from shadycompass.facts import PublicTarget
from shadycompass.rules.http_spider.katana import KatanaRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn


class KatanaRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_spider, KatanaRules.katana_tool_name, True)

    def test_katana_private(self):
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl'],
        ), self.engine)

    def test_katana_private_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5'],
        ), self.engine)

    def test_katana_private_options(self):
        self.engine.config_set(SECTION_OPTIONS, KatanaRules.katana_tool_name, '-known-files robotstxt', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'robotstxt', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'robotstxt', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl'],
        ), self.engine)

    def test_katana_private_ratelimit_options(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_OPTIONS, KatanaRules.katana_tool_name, '-known-files robotstxt', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'robotstxt', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5'],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'robotstxt', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5'],
        ), self.engine)

    def test_katana_public(self):
        self.engine.declare(PublicTarget(addr='10.129.229.189'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl',
                          '-passive',
                          ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl',
                          '-passive',
                          ],
        ), self.engine)

    def test_katana_public_ratelimit(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.declare(PublicTarget(addr='10.129.229.189'))
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'http://shadycompass.test:8080',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-8080-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5',
                          '-passive',
                          ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_spider,
            name=KatanaRules.katana_tool_name,
            command_line=['-u', 'https://shadycompass.test:443',
                          '-js-crawl',
                          '-known-files', 'all', '-form-extraction',
                          '-o', 'katana-443-shadycompass.test.json', '-jsonl',
                          '-rate-limit', '5',
                          '-passive',
                          ],
        ), self.engine)

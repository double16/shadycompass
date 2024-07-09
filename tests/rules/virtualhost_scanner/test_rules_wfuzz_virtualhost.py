from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION, SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN
from shadycompass.rules.http_buster.wfuzz import WfuzzRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class WfuzzVirtualHostTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_wfuzz(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, WfuzzRules.wfuzz_tool_name, True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-8080-shadycompass.test.json,json',
                'http://FUZZ.shadycompass.test:8080/',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-443-shadycompass.test.json,json',
                'https://FUZZ.shadycompass.test:443/',
            ],
        ), self.engine)

    def test_wfuzz_options(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, WfuzzRules.wfuzz_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, WfuzzRules.wfuzz_tool_name, '--hc 404,500', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404,500',
                '-f', 'wfuzz-vhost-8080-shadycompass.test.json,json',
                'http://FUZZ.shadycompass.test:8080/',
            ],
        ), self.engine)

    def test_wfuzz_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, WfuzzRules.wfuzz_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-8080-shadycompass.test.json,json',
                '-t', '1', '-s', '12',
                'http://FUZZ.shadycompass.test:8080/'
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-443-shadycompass.test.json,json',
                '-t', '1', '-s', '12',
                'https://FUZZ.shadycompass.test:443/'
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-8080-shadycompass.test.json,json',
                'http://FUZZ.shadycompass.test:8080/'
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-110000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-443-shadycompass.test.json,json',
                'https://FUZZ.shadycompass.test:443/'
            ],
        ), self.engine)

    def test_wfuzz_wordlist(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, WfuzzRules.wfuzz_tool_name, True)
        self.engine.config_set(SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN, 'subdomains-top1million-5000.txt', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-5000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-8080-shadycompass.test.json,json',
                'http://FUZZ.shadycompass.test:8080/',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=WfuzzRules.wfuzz_tool_name,
            command_line=[
                '-w', 'subdomains-top1million-5000.txt',
                '--hc', '404',
                '-f', 'wfuzz-vhost-443-shadycompass.test.json,json',
                'https://FUZZ.shadycompass.test:443/',
            ],
        ), self.engine)

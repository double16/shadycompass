from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, OPTION_RATELIMIT, \
    OPTION_PRODUCTION, SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN
from shadycompass.rules.http_buster.gobuster import GoBusterRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class GobusterVirtualHostTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_gobuster(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, GoBusterRules.gobuster_tool_name, True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-8080-shadycompass.test.txt",
                '--append-domain',
                '-u', 'http://shadycompass.test:8080',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-443-shadycompass.test.txt",
                '--append-domain',
                '-u', 'https://shadycompass.test:443',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)

    def test_gobuster_options(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, GoBusterRules.gobuster_tool_name, '--retry', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-8080-shadycompass.test.txt",
                '--append-domain',
                '-u', 'http://shadycompass.test:8080', '--retry',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)

    def test_gobuster_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-8080-shadycompass.test.txt",
                '--append-domain',
                '-u', 'http://shadycompass.test:8080',
                '--threads', '1', '--delay', '12000ms',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-443-shadycompass.test.txt",
                '--append-domain',
                '-u', 'https://shadycompass.test:443',
                '--threads', '1', '--delay', '12000ms',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-8080-shadycompass.test.txt",
                '--append-domain',
                '-u', 'http://shadycompass.test:8080',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-443-shadycompass.test.txt",
                '--append-domain',
                '-u', 'https://shadycompass.test:443',
                '-w', 'subdomains-top1million-110000.txt',
            ],
        ), self.engine)

    def test_gobuster_wordlist(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.virtualhost_scanner, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_WORDLISTS, OPTION_WORDLIST_SUBDOMAIN, 'subdomains-top1million-5000.txt', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-8080-shadycompass.test.txt",
                '--append-domain',
                '-u', 'http://shadycompass.test:8080',
                '-w', 'subdomains-top1million-5000.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.virtualhost_scanner,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'vhost', '-k',
                '-o', "gobuster-vhost-443-shadycompass.test.txt",
                '--append-domain',
                '-u', 'https://shadycompass.test:443',
                '-w', 'subdomains-top1million-5000.txt',
            ],
        ), self.engine)

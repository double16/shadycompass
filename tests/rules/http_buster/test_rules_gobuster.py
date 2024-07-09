from shadycompass.config import SECTION_TOOLS, ToolCategory, ToolRecommended, SECTION_OPTIONS, SECTION_DEFAULT, \
    OPTION_RATELIMIT, OPTION_PRODUCTION, SECTION_WORDLISTS, OPTION_WORDLIST_FILE
from shadycompass.rules.http_buster.gobuster import GoBusterRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


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
                '-o', "gobuster-8080-shadycompass.test.txt",
                '-u', 'http://shadycompass.test:8080',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-443-shadycompass.test.txt",
                '-u', 'https://shadycompass.test:443',
                '-w', 'raft-large-files.txt',
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
                '-o', "gobuster-8080-shadycompass.test.txt",
                '-u', 'http://shadycompass.test:8080', '--retry',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)

    def test_gobuster_ratelimit(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_RATELIMIT, '5', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-8080-shadycompass.test.txt",
                '-u', 'http://shadycompass.test:8080',
                '--threads', '1', '--delay', '12000ms',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-443-shadycompass.test.txt",
                '-u', 'https://shadycompass.test:443',
                '--threads', '1', '--delay', '12000ms',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-8080-shadycompass.test.txt",
                '-u', 'http://shadycompass.test:8080',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-443-shadycompass.test.txt",
                '-u', 'https://shadycompass.test:443',
                '-w', 'raft-large-files.txt',
            ],
        ), self.engine)

    def test_gobuster_wordlist(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, GoBusterRules.gobuster_tool_name, True)
        self.engine.config_set(SECTION_WORDLISTS, OPTION_WORDLIST_FILE, 'raft-medium-files.txt', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-8080-shadycompass.test.txt",
                '-u', 'http://shadycompass.test:8080',
                '-w', 'raft-medium-files.txt',
            ],
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.http_buster,
            name=GoBusterRules.gobuster_tool_name,
            command_line=[
                'dir', '-k',
                '-o', "gobuster-443-shadycompass.test.txt",
                '-u', 'https://shadycompass.test:443',
                '-w', 'raft-medium-files.txt',
            ],
        ), self.engine)

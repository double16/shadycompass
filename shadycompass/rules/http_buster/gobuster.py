from experta import Rule, DefFacts, OR, AS

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import HttpBustingNeeded
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class GoBusterRules:
    gobuster_tool_name = 'gobuster'

    @DefFacts()
    def gobuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            tool_links=[
                'https://github.com/OJ/gobuster',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(),
        OR(PreferredTool(category=ToolCategory.http_buster, name=gobuster_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL))
    )
    def run_gobuster(self, f1: HttpBustingNeeded):
        self.declare(ToolRecommended(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            command_line=[
                'dir', '--random-agent', '--discover-backup', '-k',
                '-o', f"gobuster-{f1.get_port()}-{f1.get_vhost()}.txt",
                '-u', f1.get_url(),
            ],
        ))

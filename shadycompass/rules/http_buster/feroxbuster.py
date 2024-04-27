from experta import Rule, DefFacts, OR, AS

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import HttpBustingNeeded
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class FeroxBusterRules:
    feroxbuster_tool_name = 'feroxbuster'

    @DefFacts()
    def feroxbuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.feroxbuster_tool_name,
            tool_links=[
                'https://github.com/epi052/feroxbuster',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(),
        OR(PreferredTool(category=ToolCategory.http_buster, name=feroxbuster_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL))
    )
    def run_feroxbuster(self, f1: HttpBustingNeeded):
        self.declare(ToolRecommended(
            category=ToolCategory.http_buster,
            name=self.feroxbuster_tool_name,
            command_line=[
                '-u', f1.get_url(), '--random-agent', '--extract-links',
                '-o', f"feroxbuster-{f1.get_port()}-{f1.get_vhost()}.txt", '--thorough',
                '--scan-limit', '6', '--insecure',
            ],
        ))

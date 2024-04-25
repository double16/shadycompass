from experta import Rule, DefFacts, OR, AS

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import HttpBustingNeeded


class FeroxBusterRules:
    feroxbuster_tool_name = 'feroxbuster'

    @DefFacts()
    def feroxbuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.feroxbuster_tool_name
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
            command_line=[f1.get_url()],
        ))

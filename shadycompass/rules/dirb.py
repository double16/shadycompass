from experta import Rule, DefFacts, AS, OR

from shadycompass.config import ToolCategory, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended, PreferredTool
from shadycompass.facts import HttpBustingNeeded


class DirbRules:
    dirb_tool_name = 'dirb'

    @DefFacts()
    def dirb_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.dirb_tool_name
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(),
        OR(PreferredTool(category=ToolCategory.http_buster, name=dirb_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL))
    )
    def run_dirb(self, f1: HttpBustingNeeded):
        self.declare(ToolRecommended(
            category=ToolCategory.http_buster,
            name=self.dirb_tool_name,
            command_line=[f1.get_url()],
        ))

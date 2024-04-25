from experta import Rule, DefFacts, OR, AS

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import HttpBustingNeeded


class WfuzzRules:
    wfuzz_tool_name = 'wfuzz'

    @DefFacts()
    def wfuzz_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(),
        OR(PreferredTool(category=ToolCategory.http_buster, name=wfuzz_tool_name),
           PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL))
    )
    def run_wfuzz(self, f1: HttpBustingNeeded):
        self.declare(ToolRecommended(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            command_line=[f1.get_url()],
        ))

from experta import Rule, DefFacts, OR, AS

from shadycompass.config import ToolCategory, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import HttpBustingNeeded
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE


class WfuzzRules:
    wfuzz_tool_name = 'wfuzz'

    @DefFacts()
    def wfuzz_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            tool_links=[
                'http://www.edge-security.com/wfuzz.php',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
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
            command_line=[
                '-w', '/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt',
                '--hc', '404',
                '-f', f'wfuzz-{f1.get_port()}-{f1.get_vhost()}.json,json',
                f'{f1.get_url()}/FUZZ',
            ],
        ))

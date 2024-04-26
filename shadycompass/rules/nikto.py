from experta import DefFacts

from shadycompass.config import ToolAvailable, ToolCategory


class NiktoRules:
    nikto_tool_name = "nikto"

    @DefFacts()
    def nikto_available(self):
        yield ToolAvailable(
            category=ToolCategory.vuln_scanner,
            name=self.nikto_tool_name
        )

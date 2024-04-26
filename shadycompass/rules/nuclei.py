from experta import DefFacts

from shadycompass.config import ToolAvailable, ToolCategory


class NucleiRules:
    nuclei_tool_name = "nuclei"

    @DefFacts()
    def nuclei_available(self):
        yield ToolAvailable(
            category=ToolCategory.vuln_scanner,
            name=self.nuclei_tool_name
        )

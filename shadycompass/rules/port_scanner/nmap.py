from experta import DefFacts

from shadycompass.config import ToolAvailable, ToolCategory


class NmapRules:
    nmap_tool_name = "nmap"
    rustscan_tool_name = "rustscan"

    @DefFacts()
    def nmap_available(self):
        yield ToolAvailable(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name
        )
        yield ToolAvailable(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name
        )

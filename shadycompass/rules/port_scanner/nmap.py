from experta import DefFacts, Rule, AS, OR, NOT

from shadycompass.config import ToolAvailable, ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import PortScanNeeded


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

    @Rule(
        AS.f1 << PortScanNeeded(),
        OR(
            PreferredTool(category=ToolCategory.port_scanner, name=nmap_tool_name),
            PreferredTool(category=ToolCategory.port_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.port_scanner)),
        )
    )
    def run_nmap(self, f1: PortScanNeeded):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'
        self.declare(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name,
            command_line=[
                '-p-', '-sV', '-sC', '-oN', 'tcp-all.txt', '-oX', 'tcp-all.xml', addr
            ],
        ))
        self.declare(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name,
            command_line=[
                '--top-ports=100', '-sV', '-sC', '-oN', 'tcp-100.txt', '-oX', 'tcp-100.xml', addr
            ],
        ))

    @Rule(
        AS.f1 << PortScanNeeded(),
        OR(
            PreferredTool(category=ToolCategory.port_scanner, name=rustscan_tool_name),
            PreferredTool(category=ToolCategory.port_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.port_scanner)),
        )
    )
    def run_rustscan(self, f1: PortScanNeeded):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'
        self.declare(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name,
            command_line=[
                '-a', addr, '--', '-sV', '-sC', '-oN', 'tcp-all.txt', '-oX', 'tcp-all.xml'
            ],
        ))
        self.declare(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name,
            command_line=[
                '--top', addr, '--', '-sV', '-sC', '-oN', 'tcp-1000.txt', '-oX', 'tcp-1000.xml'
            ],
        ))

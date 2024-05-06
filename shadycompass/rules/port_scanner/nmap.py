from abc import ABC

from experta import DefFacts, Rule, AS, OR, NOT, MATCH

from shadycompass.config import ToolAvailable, ToolCategory, PreferredTool, OPTION_VALUE_ALL, ToolRecommended
from shadycompass.facts import ScanNeeded, RateLimitEnable
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_NETWORK


class NmapRules(IRules, ABC):
    nmap_tool_name = "nmap"
    rustscan_tool_name = "rustscan"

    @DefFacts()
    def nmap_available(self):
        yield ToolAvailable(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name,
            tool_links=[
                'https://nmap.org/',
                'https://www.kali.org/tools/nmap/',
            ],
            methodology_links=METHOD_NETWORK,
        )
        yield ToolAvailable(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name,
            tool_links=[
                'https://github.com/RustScan/RustScan',
            ],
            methodology_links=METHOD_NETWORK,
        )

    def _declare_nmap(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'
            addr_file_name_part = ''
        else:
            addr_file_name_part = f'-{addr}'

        more_options = []
        if ratelimit:
            more_options.append(['--max-rate', str(ratelimit.get_request_per_second())])

        command_line_all = self.resolve_command_line(
            self.nmap_tool_name,
            [
                '-p-', '-sV', '-sC',
                '-oN', f'nmap{addr_file_name_part}-tcp-all.txt',
                '-oX', f'nmap{addr_file_name_part}-tcp-all.xml'
            ], *more_options
        )
        command_line_all.append(addr)
        self.recommend_tool(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name,
            variant='all',
            command_line=command_line_all,
            addr=f1.get_addr(),
        )

        command_line_top100 = self.resolve_command_line(
            self.nmap_tool_name,
            [
                '--top-ports=100', '-sV', '-sC',
                '-oN', f'nmap{addr_file_name_part}-tcp-100.txt',
                '-oX', f'nmap{addr_file_name_part}-tcp-100.xml'
            ], *more_options
        )
        command_line_top100.append(addr)
        self.recommend_tool(
            category=ToolCategory.port_scanner,
            name=self.nmap_tool_name,
            variant='top100',
            command_line=command_line_top100,
            addr=f1.get_addr(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.port_scanner, addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.port_scanner, name=nmap_tool_name),
            PreferredTool(category=ToolCategory.port_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.port_scanner)),
        ),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_nmap(self, f1: ScanNeeded):
        self._declare_nmap(f1)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.port_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.port_scanner, name=nmap_tool_name),
            PreferredTool(category=ToolCategory.port_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.port_scanner)),
        ),
    )
    def run_nmap_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable):
        self._declare_nmap(f1, ratelimit)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.port_scanner, addr=MATCH.addr),
        OR(
            PreferredTool(category=ToolCategory.port_scanner, name=rustscan_tool_name),
            PreferredTool(category=ToolCategory.port_scanner, name=OPTION_VALUE_ALL),
            NOT(PreferredTool(category=ToolCategory.port_scanner)),
        ),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_rustscan(self, f1: ScanNeeded):
        addr = f1.get_addr()
        if not addr:
            addr = '$IP'
            addr_file_name_part = ''
        else:
            addr_file_name_part = f'-{addr}'

        command_line_all = self.resolve_command_line(
            self.rustscan_tool_name,
            [
                '-a', addr, '--', '-sV', '-sC',
                '-oN', f'nmap{addr_file_name_part}-tcp-all.txt',
                '-oX', f'nmap{addr_file_name_part}-tcp-all.xml'
            ]
        )
        self.recommend_tool(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name,
            variant='all',
            command_line=command_line_all,
            addr=f1.get_addr(),
        )

        command_line_top = self.resolve_command_line(
            self.rustscan_tool_name,
            [
                '--top', addr, '--', '-sV', '-sC',
                '-oN', f'nmap{addr_file_name_part}-tcp-1000.txt',
                '-oX', f'nmap{addr_file_name_part}-tcp-1000.xml'
            ]
        )
        self.recommend_tool(
            category=ToolCategory.port_scanner,
            name=self.rustscan_tool_name,
            variant='top',
            command_line=command_line_top,
            addr=f1.get_addr(),
        )

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.port_scanner, name=rustscan_tool_name, addr=MATCH.addr),
        RateLimitEnable(addr=MATCH.addr),
    )
    def retract_rustscan(self, f1: ToolRecommended):
        self.retract(f1)

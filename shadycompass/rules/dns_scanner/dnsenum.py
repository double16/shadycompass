from abc import ABC

from experta import DefFacts

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DnsEnumRules(IRules, ABC):
    dnsenum_tool_name = 'dnsenum'

    @DefFacts()
    def dnsenum_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dnsenum_tool_name,
            tool_links=[
                'https://github.com/SparrowOchon/dnsenum2',
                'https://www.kali.org/tools/dnsenum/',
            ],
            methodology_links=METHOD_DNS,
        )

    # dnsenum --dnsserver 10.129.229.189 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt hospital.htb

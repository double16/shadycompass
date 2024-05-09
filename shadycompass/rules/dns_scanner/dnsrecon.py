from abc import ABC

from experta import DefFacts

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DnsReconRules(IRules, ABC):
    dnsrecon_tool_name = 'dnsrecon'

    @DefFacts()
    def dnsrecon_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dnsrecon_tool_name,
            tool_links=[
                'https://github.com/darkoperator/dnsrecon',
                'https://www.kali.org/tools/dnsrecon/',
            ],
            methodology_links=METHOD_DNS,
        )

# dnsrecon -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -d hospital.htb -n 10.129.229.189

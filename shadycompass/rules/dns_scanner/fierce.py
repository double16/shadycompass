from abc import ABC

from experta import DefFacts

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class FierceRules(IRules, ABC):
    fierce_tool_name = 'fierce'

    @DefFacts()
    def dnsrecon_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.fierce_tool_name,
            tool_links=[
                'https://github.com/mschwager/fierce',
                'https://www.kali.org/tools/fierce/',
            ],
            methodology_links=METHOD_DNS,
        )

    # fierce --domain hospital.htb --dns-servers 10.129.229.189 | tee fierce-shadycompass.test.txt

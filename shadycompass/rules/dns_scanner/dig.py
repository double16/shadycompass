from abc import ABC

from experta import DefFacts

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DigRules(IRules, ABC):
    dig_tool_name = 'dig'

    @DefFacts()
    def dig_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dig_tool_name,
            tool_links=[
                'https://www.isc.org/bind/',
            ],
            methodology_links=METHOD_DNS,
        )

    # dig axfr @10.129.229.189 hospital.htb | tee dig-axfr-hospital.htb.txt
    # dig any hospital.htb @hospital.htb | tee dig-any-shadycompass.test.txt

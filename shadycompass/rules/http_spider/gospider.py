from abc import ABC

from experta import DefFacts

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_AUTOMATIC_SCANNERS


class GospiderRules(IRules, ABC):
    gospider_tool_name = 'gospider'

    @DefFacts()
    def gospider_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_spider,
            name=self.gospider_tool_name,
            tool_links=[
                'https://github.com/jaeles-project/gospider',
            ],
            methodology_links=METHOD_HTTP_AUTOMATIC_SCANNERS,
        )

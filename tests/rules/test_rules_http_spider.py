from base import RulesBase
from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent

from shadycompass.rules.http_spider.katana import KatanaRules
from tests.tests import assertFactIn, assertFactNotIn


class HttpSpiderTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_spider, value=KatanaRules.katana_tool_name,
                       global0=True))
        self.engine.run()

    def test_http_spider_needed(self):
        assertFactIn(ScanNeeded(category=ToolCategory.http_spider, secure=True, addr='10.129.229.189', port=443,
                                hostname='shadycompass.test'),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.http_spider, secure=False, addr='10.129.229.189', port=8080,
                                hostname='shadycompass.test'),
                     self.engine)

    def test_http_spider_not_needed(self):
        self.engine.declare(
            ScanPresent(category=ToolCategory.http_spider, name=KatanaRules.katana_tool_name, secure=True,
                        addr='10.129.229.189', port=443, hostname='shadycompass.test'))
        self.engine.declare(
            ScanPresent(category=ToolCategory.http_spider, name=KatanaRules.katana_tool_name, secure=False,
                        addr='10.129.229.189', port=8080, hostname='shadycompass.test'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.http_spider, secure=True, addr='10.129.229.189', port=443,
                                   hostname='shadycompass.test'),
                        self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.http_spider, secure=False, addr='10.129.229.189', port=8080,
                                   hostname='shadycompass.test'),
                        self.engine)

    def test_http_spider_retract(self):
        self.engine.run()
        self.engine.declare(
            ScanPresent(category=ToolCategory.http_spider, name=KatanaRules.katana_tool_name, secure=True,
                        addr='10.129.229.189', port=443, hostname='shadycompass.test'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.http_spider, secure=True, addr='10.129.229.189', port=443,
                                   hostname='shadycompass.test'),
                        self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.http_spider, secure=False, addr='10.129.229.189', port=8080,
                                hostname='shadycompass.test'),
                     self.engine)

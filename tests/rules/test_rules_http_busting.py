from base import RulesBase
from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory
from shadycompass.facts import HttpBustingNeeded, ScanPresent
from shadycompass.rules.http_buster.dirb import DirbRules
from tests.tests import assertFactIn, assertFactNotIn


class HttpBustingTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value=DirbRules.dirb_tool_name, global0=True))
        self.engine.run()

    def test_http_busting_needed(self):
        assertFactIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                     self.engine)
        assertFactIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                     self.engine)

    def test_http_busting_not_needed(self):
        self.engine.declare(ScanPresent(category=ToolCategory.http_buster, name='wfuzz', port=443,
                                        addr='10.129.229.189', hostname='shadycompass.test',
                                        url="https://shadycompass.test:443/"))
        self.engine.declare(ScanPresent(category=ToolCategory.http_buster, name='wfuzz', port=8080,
                                        addr='10.129.229.189', hostname='shadycompass.test',
                                        url="http://shadycompass.test:8080/"))
        self.engine.run()
        assertFactNotIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                        self.engine)
        assertFactNotIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                        self.engine)

    def test_http_busting_retract(self):
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.http_buster, name='wfuzz', port=443,
                                        addr='10.129.229.189', hostname='shadycompass.test',
                                        url="https://shadycompass.test:443/"))
        self.engine.run()
        assertFactNotIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                        self.engine)
        assertFactIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                     self.engine)

from base import RulesBase
from shadycompass import ConfigFact
from shadycompass.config import SECTION_TOOLS, ToolCategory
from shadycompass.facts import HttpBustingNeeded, HttpUrl
from shadycompass.rules.http_buster.dirb import DirbRules
from tests.tests import assertFactIn, assertFactNotIn


class HttpBustingTest(RulesBase):

    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value=DirbRules.dirb_tool_name, global0=True))
        self.engine.run()

    def test_httpbusting_needed(self):
        assertFactIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                     self.engine)
        assertFactIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                     self.engine)

    def test_httpbusting_not_needed(self):
        self.engine.declare(HttpUrl(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test',
                                    url="https://shadycompass.test/"))
        self.engine.declare(HttpUrl(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test',
                                    url="https://shadycompass.test/"))
        self.engine.run()
        assertFactNotIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                        self.engine)
        assertFactNotIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                        self.engine)

    def test_httpbusting_retract(self):
        self.engine.run()
        self.engine.declare(HttpUrl(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test',
                                    url="https://shadycompass.test/"))
        self.engine.run()
        assertFactNotIn(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'),
                        self.engine)
        assertFactIn(HttpBustingNeeded(secure=False, addr='10.129.229.189', port=8080, vhost='shadycompass.test'),
                     self.engine)

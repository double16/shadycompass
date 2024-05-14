from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, Kerberos5SecTcpService, Kerberos5SecUdpService
from tests.tests import assertFactIn, assertFactNotIn


class AsRepRoasterTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_asrep_roaster_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster), self.engine)

    def test_asrep_roaster_one_target(self):
        self.engine.declare(Kerberos5SecTcpService(addr='10.1.1.1', port=88))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.1'),
                     self.engine)

    def test_asrep_roaster_two_target(self):
        self.engine.declare(Kerberos5SecTcpService(addr='10.1.1.1', port=88))
        self.engine.declare(Kerberos5SecUdpService(addr='10.1.1.2', port=88))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.1'),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.2'),
                     self.engine)

    def test_asrep_roaster_present1(self):
        self.engine.declare(Kerberos5SecTcpService(addr='10.1.1.1', port=88))
        self.engine.declare(ScanPresent(category=ToolCategory.asrep_roaster, name='nmap', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.1'), self.engine)

    def test_asrep_roaster_present2(self):
        self.engine.declare(Kerberos5SecTcpService(addr='10.1.1.1', port=88))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.asrep_roaster, name='nmap', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.asrep_roaster, addr='10.1.1.1'), self.engine)

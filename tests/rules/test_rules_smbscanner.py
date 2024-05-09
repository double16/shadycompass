from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, SmbService, NetbiosNameService, NetbiosSessionService, \
    NetbiosDatagramService
from tests.tests import assertFactIn, assertFactNotIn


class SmbScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_smbscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner), self.engine)

    def test_smbscan_one_target(self):
        self.engine.declare(SmbService(addr='10.1.1.1', port=445))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_two_target(self):
        self.engine.declare(SmbService(addr='10.1.1.1', port=445))
        self.engine.declare(SmbService(addr='10.1.1.2', port=445))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.2'), self.engine)

    def test_smbscan_present1(self):
        self.engine.declare(SmbService(addr='10.1.1.1', port=445))
        self.engine.declare(ScanPresent(category=ToolCategory.smb_scanner, name='enum4linux-ng', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_present2(self):
        self.engine.declare(SmbService(addr='10.1.1.1', port=445))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.smb_scanner, name='enum4linux-ng', addr='10.1.1.1'))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_one_netbios_ns(self):
        self.engine.declare(NetbiosNameService(addr='10.1.1.1', port=137))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_one_netbios_dgm(self):
        self.engine.declare(NetbiosDatagramService(addr='10.1.1.1', port=138))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_one_netbios_ssn(self):
        self.engine.declare(NetbiosSessionService(addr='10.1.1.1', port=139))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

    def test_smbscan_one_netbios_all(self):
        self.engine.declare(NetbiosNameService(addr='10.1.1.1', port=137))
        self.engine.declare(NetbiosDatagramService(addr='10.1.1.1', port=138))
        self.engine.declare(NetbiosSessionService(addr='10.1.1.1', port=139))
        self.engine.declare(SmbService(addr='10.1.1.1', port=445))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smb_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smb_scanner, addr='10.1.1.1'), self.engine)

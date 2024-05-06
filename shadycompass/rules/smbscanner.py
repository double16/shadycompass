from abc import ABC

from experta import Rule, NOT, OR, MATCH, AS

from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, SmbService, \
    NetbiosNameService, NetbiosDatagramService, NetbiosSessionService
from shadycompass.rules.irules import IRules


class SmbScan(IRules, ABC):
    @Rule(
        OR(
            NetbiosNameService(addr=MATCH.addr),
            NetbiosDatagramService(addr=MATCH.addr),
            NetbiosSessionService(addr=MATCH.addr),
            SmbService(addr=MATCH.addr)
        ),
        NOT(ScanPresent(category=ToolCategory.smb_scanner, addr=MATCH.addr)),
        salience=100
    )
    def need_smb_scan_addr(self, addr):
        self.declare(ScanNeeded(category=ToolCategory.smb_scanner, addr=addr))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smb_scanner, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.smb_scanner, addr=MATCH.addr),
    )
    def do_not_need_smb_scan(self, f1: ScanNeeded):
        self.retract(f1)

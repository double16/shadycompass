from abc import ABC

from experta import Rule, NOT, OR, MATCH, AS

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, Kerberos5SecTcpService, Kerberos5SecUdpService
from shadycompass.rules.irules import IRules


class AsRepRoaster(IRules, ABC):
    @Rule(
        OR(
            Kerberos5SecTcpService(addr=MATCH.addr),
            Kerberos5SecUdpService(addr=MATCH.addr),
        ),
        NOT(ScanPresent(category=ToolCategory.asrep_roaster, addr=MATCH.addr)),
        salience=100
    )
    def need_asrep_roaster_addr(self, addr):
        self.declare(ScanNeeded(category=ToolCategory.asrep_roaster, addr=addr))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
    )
    def do_not_need_asrep_roaster(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.asrep_roaster, addr=MATCH.addr),
    )
    def retract_asrep_roaster(self, f1: ToolRecommended):
        self.retract(f1)

from abc import ABC

from experta import Rule, NOT, MATCH, AS

from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, PopService
from shadycompass.rules.irules import IRules


class PopScan(IRules, ABC):
    @Rule(
        PopService(addr=MATCH.addr, port=MATCH.port),
        NOT(ScanPresent(category=ToolCategory.pop_scanner, addr=MATCH.addr, port=MATCH.port)),
        salience=100
    )
    def need_pop_scan_addr(self, addr: str, port: int):
        self.declare(ScanNeeded(category=ToolCategory.pop_scanner, addr=addr, port=port))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.pop_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.pop_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def do_not_need_pop_scan(self, f1: ScanNeeded):
        self.retract(f1)

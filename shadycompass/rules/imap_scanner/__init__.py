from abc import ABC

from experta import Rule, NOT, MATCH, AS

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, ImapService
from shadycompass.rules.irules import IRules


class ImapScan(IRules, ABC):
    @Rule(
        ImapService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
        NOT(ScanPresent(category=ToolCategory.imap_scanner, addr=MATCH.addr, port=MATCH.port)),
        salience=100
    )
    def need_imap_scan_addr(self, addr: str, port: int, secure: bool):
        self.declare(ScanNeeded(category=ToolCategory.imap_scanner, addr=addr, port=port, secure=secure))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.imap_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.imap_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def do_not_need_imap_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.imap_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.imap_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def retract_imap(self, f1: ToolRecommended):
        self.retract(f1)

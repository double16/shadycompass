from abc import ABC

from experta import Rule, NOT, MATCH, AS

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, SmtpService
from shadycompass.rules.irules import IRules


class SmtpScan(IRules, ABC):
    @Rule(
        SmtpService(addr=MATCH.addr, port=MATCH.port, secure=MATCH.secure),
        NOT(ScanPresent(category=ToolCategory.smtp_scanner, addr=MATCH.addr, port=MATCH.port)),
        salience=100
    )
    def need_smtp_scan_addr(self, addr: str, port: int, secure: bool):
        self.declare(ScanNeeded(category=ToolCategory.smtp_scanner, addr=addr, port=port, secure=secure))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smtp_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.smtp_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def do_not_need_smtp_scan(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.smtp_scanner, addr=MATCH.addr, port=MATCH.port),
        ScanPresent(category=ToolCategory.smtp_scanner, addr=MATCH.addr, port=MATCH.port),
    )
    def retract_smtp_tool(self, f1: ToolRecommended):
        self.retract(f1)

from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, SmtpService
from tests.tests import assertFactIn, assertFactNotIn


class SmtpScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_smtpscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner), self.engine)

    def test_smtpscan_one_target(self):
        self.engine.declare(SmtpService(addr='10.1.1.1', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.1.1.1', port=587, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=25, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=587, secure=True),
                     self.engine)

    def test_smtpscan_two_target(self):
        self.engine.declare(SmtpService(addr='10.1.1.1', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.1.1.1', port=587, secure=True))
        self.engine.declare(SmtpService(addr='10.1.1.2', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.1.1.2', port=587, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=25, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=587, secure=True),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.2', port=25, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.2', port=587, secure=True),
                     self.engine)

    def test_smtpscan_present1(self):
        self.engine.declare(SmtpService(addr='10.1.1.1', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.1.1.1', port=587, secure=True))
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name='nmap', addr='10.1.1.1', port=25))
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name='nmap', addr='10.1.1.1', port=587))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=25), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=587), self.engine)

    def test_smtpscan_present2(self):
        self.engine.declare(SmtpService(addr='10.1.1.1', port=25, secure=False))
        self.engine.declare(SmtpService(addr='10.1.1.1', port=587, secure=True))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name='nmap', addr='10.1.1.1', port=25))
        self.engine.declare(ScanPresent(category=ToolCategory.smtp_scanner, name='nmap', addr='10.1.1.1', port=587))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=25), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.smtp_scanner, addr='10.1.1.1', port=587), self.engine)

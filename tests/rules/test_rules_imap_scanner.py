from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, ImapService
from tests.tests import assertFactIn, assertFactNotIn


class ImapScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_imapscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner), self.engine)

    def test_imapscan_one_target(self):
        self.engine.declare(ImapService(addr='10.1.1.1', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.1.1.1', port=993, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=143, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=993, secure=True),
                     self.engine)

    def test_imapscan_two_targets(self):
        self.engine.declare(ImapService(addr='10.1.1.1', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.1.1.1', port=993, secure=True))
        self.engine.declare(ImapService(addr='10.1.1.2', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.1.1.2', port=993, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=143, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=993, secure=True),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.2', port=143, secure=False),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.2', port=993, secure=True),
                     self.engine)

    def test_imapscan_present1(self):
        self.engine.declare(ImapService(addr='10.1.1.1', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.1.1.1', port=993, secure=True))
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name='nmap', addr='10.1.1.1', port=143))
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name='nmap', addr='10.1.1.1', port=993))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=143), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=993), self.engine)

    def test_imapscan_present2(self):
        self.engine.declare(ImapService(addr='10.1.1.1', port=143, secure=False))
        self.engine.declare(ImapService(addr='10.1.1.1', port=993, secure=True))
        self.engine.run()
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name='nmap', addr='10.1.1.1', port=143))
        self.engine.declare(ScanPresent(category=ToolCategory.imap_scanner, name='nmap', addr='10.1.1.1', port=993))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=143), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.imap_scanner, addr='10.1.1.1', port=993), self.engine)

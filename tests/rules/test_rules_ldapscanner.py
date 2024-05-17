from base import RulesBase
from shadycompass.config import ToolCategory
from shadycompass.facts import ScanNeeded, ScanPresent, LdapService
from tests.tests import assertFactIn, assertFactNotIn


class LdapScanTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_ldapscan_no_targets(self):
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner), self.engine)

    def test_ldapscan_one_target(self):
        self.engine.declare(LdapService(addr='10.1.1.1', port=389, secure=False))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.1.1.1'),
                     self.engine)

    def test_ldapscan_two_target(self):
        self.engine.declare(LdapService(addr='10.1.1.1', port=389, secure=False))
        self.engine.declare(LdapService(addr='10.1.1.2', port=636, secure=True))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.1.1.1'),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.1.1.2'),
                     self.engine)

    def test_ldapscan_present1(self):
        self.engine.declare(LdapService(addr='10.1.1.1', port=389, secure=False))
        self.engine.declare(
            ScanPresent(category=ToolCategory.ldap_scanner, name='ldapsearch', addr='10.1.1.1', port=389))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.1.1.1'), self.engine)

    def test_ldapscan_present2(self):
        self.engine.declare(LdapService(addr='10.1.1.1', port=389, secure=False))
        self.engine.run()
        self.engine.declare(
            ScanPresent(category=ToolCategory.ldap_scanner, name='ldapsearch', addr='10.1.1.1', port=389))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr=ScanNeeded.ANY), self.engine)
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.1.1.1'), self.engine)

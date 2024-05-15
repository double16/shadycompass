from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.facts import ScanNeeded, ScanPresent
from shadycompass.rules.ldap_scanner.ldapsearch import LdapSearchRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class LdapSearchRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_ldap_scanner(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=389, secure=True),
                     self.engine)
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=636, secure=True),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x',
                '>ldapsearch-base-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x', '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x',
                '>ldapsearch-base-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x', '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=389,
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=636,
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=3268,
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189', port=3269,
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name),
                        self.engine)

    def test_ldap_scanner_options_local(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, False)
        self.engine.config_set(SECTION_OPTIONS, LdapSearchRules.ldapsearch_tool_name, '-v', False)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x', '-v',
                '>ldapsearch-base-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x', '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x', '-v',
                '>ldapsearch-base-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x', '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)

    def test_ldap_scanner_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, LdapSearchRules.ldapsearch_tool_name, '-v', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x', '-v',
                '>ldapsearch-base-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:389', '-x', '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189-389.txt'
            ],
            addr='10.129.229.189', port=389,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='base',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x', '-v',
                '>ldapsearch-base-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=[
                '-H', 'ldaps://10.129.229.189:636', '-x', '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189-636.txt'
            ],
            addr='10.129.229.189', port=636,
        ), self.engine)


class LdapSearchRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_ldap_scanner(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
        ), self.engine)

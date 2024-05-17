from shadycompass import SECTION_TOOLS
from shadycompass.config import ToolCategory, ToolRecommended, SECTION_OPTIONS
from shadycompass.facts import ScanNeeded, ScanPresent, UsernamePassword, TargetDomain, WindowsDomain
from shadycompass.rules.ldap_scanner.ldapsearch import LdapSearchRules
from tests.rules.base import RulesBase
from tests.tests import assertFactIn, assertFactNotIn


class LdapSearchRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_ldap_scanner_no_user(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '', '-b', 'DC=shadycompass,DC=test',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '', '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189',
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
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '', '-b', 'DC=shadycompass,DC=test', '-v',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '', '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)

    def test_ldap_scanner_options_global(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.config_set(SECTION_OPTIONS, LdapSearchRules.ldapsearch_tool_name, '-v', True)
        self.engine.run()
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '', '-b', 'DC=shadycompass,DC=test', '-v',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', '', '-w', '',  '-s', 'base', 'namingcontexts', '-v',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)

    def test_ldap_scanner_user(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.declare(UsernamePassword(domain='shadycompass.test', username='operator', password='12345'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'SHADYCOMPASS\\operator', '-w', '12345',
                '-b', 'DC=shadycompass,DC=test',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'SHADYCOMPASS\\operator', '-w', '12345',
                '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189',
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name),
                        self.engine)

    def test_ldap_scanner_two_domains(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.declare(UsernamePassword(domain='shadycompass.test', username='operator', password='12345'))
        self.engine.declare(TargetDomain(domain='shadycompass2.test'))
        self.engine.declare(UsernamePassword(domain='shadycompass2.test', username='operator2', password='67890'))
        for fact in list(filter(lambda e: isinstance(e, WindowsDomain), self.engine.facts.values())):
            self.engine.retract(fact)
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'operator', '-w', '12345',
                '-b', 'DC=shadycompass,DC=test',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'operator', '-w', '12345',
                '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'operator2', '-w', '67890',
                '-b', 'DC=shadycompass2,DC=test',
                '>ldapsearch-shadycompass2.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189',
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name),
                        self.engine)

    def test_ldap_scanner_windows_domain(self):
        self.engine.config_set(SECTION_TOOLS, ToolCategory.ldap_scanner, LdapSearchRules.ldapsearch_tool_name, True)
        self.engine.declare(UsernamePassword(domain='shadycompass.test', username='operator', password='12345'))
        self.engine.declare(WindowsDomain(netbios_domain_name='shadycompass2', dns_domain_name='shadycompass2.test',
                                          dns_tree_name='shadycompass2.test'))
        self.engine.declare(UsernamePassword(domain='shadycompass2.test', username='operator2', password='67890'))
        self.engine.run()
        assertFactIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'),
                     self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'SHADYCOMPASS\\operator', '-w', '12345',
                '-b', 'DC=shadycompass,DC=test',
                '>ldapsearch-shadycompass.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'SHADYCOMPASS\\operator', '-w', '12345',
                '-s', 'base', 'namingcontexts',
                '>ldapsearch-namingcontexts-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
            command_line=[
                '-H', 'ldap://10.129.229.189', '-x', '-D', 'shadycompass2\\operator2', '-w', '67890',
                '-b', 'DC=shadycompass2,DC=test',
                '>ldapsearch-shadycompass2.test-base-10.129.229.189.txt'
            ],
            addr='10.129.229.189',
        ), self.engine)
        self.engine.declare(ScanPresent(category=ToolCategory.ldap_scanner, addr='10.129.229.189',
                                        name=LdapSearchRules.ldapsearch_tool_name))
        self.engine.run()
        assertFactNotIn(ScanNeeded(category=ToolCategory.ldap_scanner, addr='10.129.229.189'), self.engine)
        assertFactNotIn(ToolRecommended(category=ToolCategory.ldap_scanner, name=LdapSearchRules.ldapsearch_tool_name),
                        self.engine)


class LdapSearchRulesNATest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(['/dev/null'], methodName)

    def test_ldap_scanner(self):
        assertFactNotIn(ToolRecommended(
            category=ToolCategory.ldap_scanner,
            name=LdapSearchRules.ldapsearch_tool_name,
        ), self.engine)

import os
import tempfile
import unittest

from parameterized import parameterized

from shadycompass import ShadyCompassEngine
from shadycompass.config import ConfigFactReader, ConfigFact, SECTION_TOOLS, ToolCategory, set_global_config_path, \
    ToolChoiceNeeded, PreferredTool, ToolAvailable, OPTION_VALUE_ALL, ToolRecommended, tool_category_priority, \
    SECTION_WORDLISTS, OPTION_WORDLIST_FILE, PreferredWordlist, OPTION_WORDLIST_USERNAME, OPTION_WORDLIST_PASSWORD, \
    OPTION_WORDLIST_SUBDOMAIN
from shadycompass.facts import HttpBustingNeeded
from tests.tests import assertFactIn, assertFactNotIn

WORDLIST_CATEGORIES = [
    OPTION_WORDLIST_FILE,
    OPTION_WORDLIST_USERNAME,
    OPTION_WORDLIST_PASSWORD,
    OPTION_WORDLIST_SUBDOMAIN,
]


class ConfigFactReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = ConfigFactReader()
        fd, self.global_config_path = tempfile.mkstemp(suffix='shadycompass.ini')
        os.write(fd, b"""[tools]
vuln_scanner = *
""")
        os.close(fd)
        set_global_config_path(self.global_config_path)

    def tearDown(self):
        os.remove(self.global_config_path)
        super().tearDown()

    def test_read_local_config(self):
        facts = self.reader.read_facts('tests/fixtures/shadycompass.ini')
        self.assertEqual(1, len(facts))
        self.assertIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False),
                      facts)

    def test_read_global_config(self):
        facts = self.reader.read_facts(self.global_config_path)
        self.assertEqual(1, len(facts))
        self.assertIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='*', global0=True),
                      facts)


class ConfigRulesTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.engine = ShadyCompassEngine([])
        self.engine.reset()
        self.engine.run()

    def test_preferred_tool_needs_chosen(self):
        assertFactIn(ToolChoiceNeeded(category=ToolCategory.port_scanner, names=['nmap', 'rustscan']), self.engine)
        assertFactIn(
            ToolChoiceNeeded(category=ToolCategory.http_buster, names=['dirb', 'feroxbuster', 'gobuster', 'wfuzz']),
            self.engine)

    def test_preferred_tool_needs_chosen2(self):
        self.engine.reset()
        self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.port_scanner, name='nmap'), self.engine)
        assertFactNotIn(ToolChoiceNeeded(category=ToolCategory.port_scanner, names=['nmap', 'rustscan']), self.engine)
        assertFactIn(
            ToolChoiceNeeded(category=ToolCategory.http_buster, names=['dirb', 'feroxbuster', 'gobuster', 'wfuzz']),
            self.engine)

    def test_implied_preferred_tool(self):
        self.engine.declare(ToolAvailable(category='test', name='only_me'))
        self.engine.run()
        assertFactIn(PreferredTool(category='test', name='only_me'), self.engine)
        assertFactNotIn(ToolChoiceNeeded(category='test', names=['only_me']), self.engine)

    def test_preferred_port_scanner_local(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.port_scanner, name='nmap'), self.engine)

    def test_preferred_port_scanner_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=True))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.port_scanner, name='nmap'), self.engine)

    def test_preferred_port_scanner_local_over_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='rustscan', global0=False))
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=True))
        self.engine.run()
        assertFactNotIn(PreferredTool(category=ToolCategory.port_scanner, name='nmap'), self.engine)
        assertFactIn(PreferredTool(category=ToolCategory.port_scanner, name='rustscan'), self.engine)

    def test_preferred_http_buster_local(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='dirb', global0=False))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.http_buster, name='dirb'), self.engine)

    def test_preferred_http_buster_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='dirb', global0=True))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.http_buster, name='dirb'), self.engine)

    def test_preferred_http_buster_local_over_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=False))
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='dirb', global0=True))
        self.engine.run()
        assertFactNotIn(PreferredTool(category=ToolCategory.http_buster, name='dirb'), self.engine)
        assertFactIn(PreferredTool(category=ToolCategory.http_buster, name='feroxbuster'), self.engine)

    def test_preferred_vuln_scanner_local(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='nuclei', global0=False))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='nuclei'), self.engine)

    def test_preferred_vuln_scanner_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='nuclei', global0=True))
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='nuclei'), self.engine)

    def test_preferred_vuln_scanner_local_over_global(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='nuclei', global0=False))
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='nikto', global0=True))
        self.engine.run()
        assertFactNotIn(PreferredTool(category=ToolCategory.vuln_scanner, name='nikto'), self.engine)
        assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='nuclei'), self.engine)

    def test_preferred_tool_retracts_other_tool_recommendations(self):
        t1 = ToolRecommended(category=ToolCategory.http_buster, name='dirb')
        t2 = ToolRecommended(category=ToolCategory.http_buster, name='wfuzz')
        t3 = ToolRecommended(category=ToolCategory.http_buster, name='gobuster')
        t4 = ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster')

        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, OPTION_VALUE_ALL, False)
        self.engine.declare(HttpBustingNeeded(secure=True, addr='10.129.229.189', port=443, vhost='shadycompass.test'))
        self.engine.run()
        assertFactIn(t1, self.engine)
        assertFactIn(t2, self.engine)
        assertFactIn(t3, self.engine)
        assertFactIn(t4, self.engine)

        self.engine.config_set(SECTION_TOOLS, ToolCategory.http_buster, 'feroxbuster', False)
        self.engine.run()
        assertFactIn(PreferredTool(category=ToolCategory.http_buster, name='feroxbuster'), self.engine)
        assertFactNotIn(PreferredTool(category=ToolCategory.http_buster, name=OPTION_VALUE_ALL), self.engine)
        assertFactNotIn(t1, self.engine)
        assertFactNotIn(t2, self.engine)
        assertFactNotIn(t3, self.engine)
        assertFactIn(t4, self.engine)

    def test_default_wordllist_file(self):
        self.engine.run()
        assertFactIn(PreferredWordlist(category=OPTION_WORDLIST_FILE, path='raft-large-files.txt', default=True),
                     self.engine)

    def test_default_wordllist_username(self):
        self.engine.run()
        assertFactIn(PreferredWordlist(category=OPTION_WORDLIST_USERNAME, path='xato-net-10-million-usernames.txt',
                                       default=True), self.engine)

    def test_default_wordllist_password(self):
        self.engine.run()
        assertFactIn(PreferredWordlist(category=OPTION_WORDLIST_PASSWORD, path='rockyou.txt', default=True),
                     self.engine)

    def test_default_wordllist_subdomain(self):
        self.engine.run()
        assertFactIn(PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN, path='subdomains-top1million-110000.txt',
                                       default=True), self.engine)

    @parameterized.expand(WORDLIST_CATEGORIES)
    def test_preferred_wordlist_global(self, category: str):
        self.engine.declare(
            ConfigFact(section=SECTION_WORDLISTS, option=category, value='wordlist1.txt', global0=True))
        self.engine.run()
        assertFactIn(PreferredWordlist(category=category, path='wordlist1.txt', default=False), self.engine)

    @parameterized.expand(WORDLIST_CATEGORIES)
    def test_preferred_wordlist_local(self, category: str):
        self.engine.declare(
            ConfigFact(section=SECTION_WORDLISTS, option=category, value='wordlist2.txt', global0=False))
        self.engine.run()
        assertFactIn(PreferredWordlist(category=category, path='wordlist2.txt', default=False), self.engine)

    @parameterized.expand(WORDLIST_CATEGORIES)
    def test_preferred_wordlist_local_over_global(self, category: str):
        self.engine.declare(
            ConfigFact(section=SECTION_WORDLISTS, option=category, value='wordlist1.txt', global0=True))
        self.engine.declare(
            ConfigFact(section=SECTION_WORDLISTS, option=category, value='wordlist2.txt', global0=False))
        self.engine.run()
        assertFactIn(PreferredWordlist(category=category, path='wordlist2.txt', default=False), self.engine)


class ToolCategoryTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_tool_category_priority(self):
        for k, v in ToolCategory.__dict__.items():
            if k.startswith('__') or not isinstance(v, str):
                continue
            priority = tool_category_priority(v)
            self.assertNotEqual(100, priority, f"ToolCategory.{k} missing in tool_category_priority(...) function")

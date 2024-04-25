import os
import tempfile
import unittest

from shadycompass import ShadyCompassEngine
from shadycompass.config import ConfigFactReader, ConfigFact, SECTION_TOOLS, ToolCategory, set_global_config_path, \
    ToolChoiceNeeded, PreferredTool, ToolAvailable
from tests.tests import assertFactIn, assertFactNotIn


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

    # def test_preferred_vuln_scanner_local(self):
    #     self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner.name, value='dirb', global0=False))
    #     self.engine.run()
    #     assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='dirb'), self.engine)
    #
    # def test_preferred_vuln_scanner_global(self):
    #     self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner.name, value='dirb', global0=True))
    #     self.engine.run()
    #     assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='dirb'), self.engine)
    #
    # def test_preferred_vuln_scanner_local_over_global(self):
    #     self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner.name, value='feroxbuster', global0=False))
    #     self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner.name, value='dirb', global0=True))
    #     self.engine.run()
    #     assertFactNotIn(PreferredTool(category=ToolCategory.vuln_scanner, name='dirb'), self.engine)
    #     assertFactIn(PreferredTool(category=ToolCategory.vuln_scanner, name='feroxbuster'), self.engine)

import os.path
import shutil
import tempfile
import unittest
from configparser import ConfigParser

from shadycompass import ConfigFact, ShadyCompassEngine
from shadycompass.config import SECTION_TOOLS, ToolCategory, set_local_config_path, set_global_config_path
from shadycompass.facts import HostnameIPv4Resolution
from tests.tests import assertFactIn, assertFactNotIn


class ShadyCompassEngineTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.local_dir = tempfile.mkdtemp()
        self.local_config = os.path.join(self.local_dir, 'shadycompass.ini')
        set_local_config_path(self.local_config)
        self.global_dir = tempfile.mkdtemp()
        self.global_config = os.path.join(self.global_dir, 'shadycompass.ini')
        set_global_config_path(self.global_config)
        self.engine = ShadyCompassEngine([])

    def tearDown(self):
        shutil.rmtree(self.local_dir)
        shutil.rmtree(self.global_dir)
        super().tearDown()

    def test_save_config(self):
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False))
        self.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.vuln_scanner, value='*', global0=True))
        self.engine.save_config()

        local_config = ConfigParser()
        local_config.read(self.local_config)
        self.assertEqual('nmap', local_config.get(SECTION_TOOLS, 'port_scanner'))

        global_config = ConfigParser()
        global_config.read(self.global_config)
        self.assertEqual('*', global_config.get(SECTION_TOOLS, 'vuln_scanner'))


class ShadyCompassEngineFactsTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.tempdir = tempfile.mkdtemp()
        shutil.copytree('tests/fixtures/nmap', self.tempdir, dirs_exist_ok=True)
        shutil.copytree('tests/fixtures/etchosts', self.tempdir, dirs_exist_ok=True)
        self.engine = ShadyCompassEngine([self.tempdir])
        self.engine.reset()
        self.engine.update_facts()
        self.engine.run()

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super().tearDown()

    def test_retract_facts(self):
        file_path = os.path.join(self.tempdir, 'hosts')
        fact = HostnameIPv4Resolution(hostname='localhost', addr='127.0.0.1')
        assertFactIn(fact, self.engine)
        os.remove(file_path)
        self.engine.update_facts()
        assertFactNotIn(fact, self.engine)


class ShadyCompassEnginePathsTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_paths(self):
        engine = ShadyCompassEngine()
        paths = engine.file_metadata.paths
        self.assertIn(os.getcwd(), paths)
        self.assertIn('/etc/hosts', paths)

import os
import shutil
import tempfile
import unittest

from shadycompass import ShadyCompassOps
from shadycompass.config import set_local_config_path, set_global_config_path, ConfigFact, SECTION_TOOLS, ToolCategory, \
    ToolRecommended
from tests.tests import assertFactIn, assertFactNotIn


class OutputCapture:
    def __init__(self):
        self.output = ''

    def write(self, text):
        self.output += text

    def flush(self):
        pass


class InputCapture:
    def __init__(self, input_string):
        self.input_string = input_string
        self.position = 0

    def read(self, size=-1):
        if size == -1:
            # Read the entire input string
            result = self.input_string[self.position:]
            self.position = len(self.input_string)
        else:
            # Read up to 'size' characters
            result = self.input_string[self.position:self.position+size]
            self.position += len(result)
        return result


class ShadyCompassOpsTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

        self.local_dir = tempfile.mkdtemp()
        self.local_config = os.path.join(self.local_dir, 'shadycompass.ini')

        self.global_dir = tempfile.mkdtemp()
        self.global_config = os.path.join(self.global_dir, 'shadycompass.ini')
        set_global_config_path(self.global_config)
        self.artifact_dir = tempfile.mkdtemp()

        self.fd_out = OutputCapture()
        self.fd_err = OutputCapture()
        self.fd_in = InputCapture('')

        self.ops = ShadyCompassOps(args=[self.artifact_dir], fd_in=self.fd_in, fd_out=self.fd_out, fd_err=self.fd_err)
        set_local_config_path(self.local_config)

    def tearDown(self):
        shutil.rmtree(self.artifact_dir)
        shutil.rmtree(self.local_dir)
        shutil.rmtree(self.global_dir)
        super().tearDown()

    def test_save_config(self):
        self.ops.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False))
        self.ops.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='wfuzz', global0=True))
        self.ops.save_config()
        # the content is verified in the test for ShadyCompassEngine
        self.assertTrue(os.stat(self.local_config).st_size > 0)
        self.assertTrue(os.stat(self.global_config).st_size > 0)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool(self):
        self.ops.use_tool(['use','feroxbuster'])
        assertFactIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool_global(self):
        self.ops.use_tool(['use','global','feroxbuster'])
        assertFactIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=True), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool_fail(self):
        try:
            self.ops.use_tool(['use','feroxbusted'])
            self.fail('feroxbusted was accepted as a tool name')
        except ValueError:
            pass

    def test_use_tool_option_fail(self):
        try:
            self.ops.use_tool(['use','feroxbusted','--nope'])
            self.fail('--nope was accepted as an option')
        except ValueError:
            pass

    def test_show_config(self):
        self.ops.use_tool(['use','feroxbuster'])
        self.ops.use_tool(['use','global','nmap'])
        self.ops.show_config()
        self.assertTrue('[tools]' in self.fd_out.output)
        self.assertTrue('# global' in self.fd_out.output)

    def test_reset_config_values(self):
        self.ops.use_tool(['use','feroxbuster'])
        self.ops.use_tool(['use','global','nmap'])
        self.ops.reset_config_values()
        configs = [fact for fact in filter(lambda f: isinstance(f, ConfigFact), self.ops.engine.facts.values())]
        self.assertEqual(0, len(configs))
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_no_section(self):
        self.ops.set_config_value(['set','ratelimit', '5'])
        assertFactIn(ConfigFact(section='general', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value(self):
        self.ops.set_config_value(['set','custom.ratelimit', '5'])
        assertFactIn(ConfigFact(section='custom', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_2dots(self):
        self.ops.set_config_value(['set','custom.rate.limit', '5'])
        assertFactIn(ConfigFact(section='custom', option='rate.limit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_global(self):
        self.ops.set_config_value(['set', 'global', 'ratelimit', '5'])
        assertFactIn(ConfigFact(section='general', option='ratelimit', value='5', global0=True), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_no_section(self):
        fact = ConfigFact(section='general', option='ratelimit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','ratelimit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value(self):
        fact = ConfigFact(section='custom', option='ratelimit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','custom.ratelimit'])
        assertFactNotIn(ConfigFact(section='custom', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_2dots(self):
        fact = ConfigFact(section='custom', option='rate.limit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','custom.rate.limit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_global(self):
        fact = ConfigFact(section='general', option='ratelimit', value='5', global0=True)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset', 'global', 'ratelimit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_tool_info1(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.tool_info(['info', '1'])
        self.assertTrue('dirb' in self.fd_out.output)

    def test_tool_info2(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '2'])
        self.assertTrue('feroxbuster' in self.fd_out.output)

    def test_tool_info3(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '1', '2'])
        self.assertTrue('dirb' in self.fd_out.output)
        self.assertTrue('feroxbuster' in self.fd_out.output)

    def test_tool_info_NAN(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', 'a'])
        self.assertTrue('[-]' in self.fd_out.output)

    def test_tool_info_index_out_of_bounds(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '10'])
        self.assertTrue('[-]' in self.fd_out.output)

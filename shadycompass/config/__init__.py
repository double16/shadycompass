import os
from abc import ABC
from configparser import ConfigParser
from typing import Union

from experta import Fact, Field, Rule, AS, MATCH, NOT

from shadycompass.facts import FactReader, fact_reader_registry
from shadycompass.rules.irules import IRules

SECTION_TOOLS = 'tools'
SECTION_OPTIONS = 'options'
SECTION_DEFAULT = 'general'
OPTION_RATELIMIT = 'ratelimit'
OPTION_PRODUCTION = 'production'
OPTION_VALUE_ALL = '*'


class ToolCategory(object):
    port_scanner = 'port_scanner'
    http_buster = 'http_buster'
    http_spider = 'http_spider'
    vhost_scanner = 'vhost_scanner'
    vuln_scanner = 'vuln_scanner'
    smb_scanner = 'smb_scanner'
    dns_scanner = 'dns_scanner'
    etc_hosts = 'hosts'


def tool_category_priority(category: str) -> int:
    """
    Returns priority for a category. Greater number is a greater priority.
    :param category:
    :return:
    """
    match category:
        case ToolCategory.etc_hosts:
            return 1000
        case ToolCategory.port_scanner:
            return 900
        case ToolCategory.dns_scanner:
            return 850
        case ToolCategory.vuln_scanner:
            return 800
        case ToolCategory.vhost_scanner:
            return 700
        case ToolCategory.http_spider:
            return 600
        case ToolCategory.http_buster:
            return 500
        case ToolCategory.smb_scanner:
            return 650
        case _:
            return 10000


class ToolAvailable(Fact):
    category = Field(str, mandatory=True)
    name = Field(str, mandatory=True)
    tool_links = Field(list[str], mandatory=False, default=[])
    methodology_links = Field(list[str], mandatory=False, default=[])

    def get_category(self):
        return self.get('category')

    def get_name(self) -> str:
        return self.get('name')

    def get_tool_links(self) -> list[str]:
        return self.get('tool_links')

    def get_methodology_links(self) -> list[str]:
        return self.get('methodology_links')


class ConfigFact(Fact):
    section = Field(str, mandatory=True)
    option = Field(object, mandatory=True)
    value = Field(str, mandatory=True)
    global0 = Field(bool, mandatory=True)


class RateLimit(Fact):
    requests_per_second = Field(int, mandatory=True)


local_config_path: Union[str, None] = None


def set_local_config_path(path: str):
    global local_config_path
    local_config_path = path


def get_local_config_path():
    global local_config_path
    if local_config_path:
        return local_config_path
    return os.path.join(os.getcwd(), 'shadycompass.ini')


global_config_path: Union[str, None] = None


def set_global_config_path(path: str):
    global global_config_path
    global_config_path = path


def get_global_config_path():
    global global_config_path
    if global_config_path:
        return global_config_path

    if os.path.isdir('/config'):
        # docker volume
        config_dir = '/config'
    else:
        # user home dir
        config_dir = os.path.join(os.path.expanduser("~"), '.config')
        if not os.path.exists(config_dir):
            os.mkdir(config_dir)
        config_dir = os.path.join(config_dir, 'shadycompass')
        if not os.path.exists(config_dir):
            os.mkdir(config_dir)
    return os.path.join(config_dir, 'shadycompass.ini')


def get_enum_from_string(enum_class, string_value):
    for enum_member in enum_class:
        if enum_member.name == string_value:
            return enum_member
    raise ValueError(f"No enum member with name '{string_value}'")


def combine_command_options(base: list[str], *args) -> list[str]:
    result = base.copy()
    for arg in args:
        if isinstance(arg, list):
            additional = arg
        else:
            additional = [str(arg)]
        if not additional:
            continue
        remove_idxs: list[int] = []
        for idx, opt in enumerate(additional[0:-1]):
            if not opt.startswith('-') or additional[idx + 1].startswith('-'):
                continue
            try:
                idx2 = result.index(opt, 0, len(result) - 1)
                if idx2 >= 0:
                    result[idx2 + 1] = additional[idx + 1]
                    remove_idxs.append(idx)
                    remove_idxs.append(idx + 1)
            except ValueError:
                pass
        remove_idxs.reverse()
        addl = additional.copy()
        for idx in remove_idxs:
            addl.pop(idx)
        result.extend(addl)
    return result


class ConfigFactReader(FactReader):
    def files(self) -> list[str]:
        return [get_global_config_path()]

    def read_facts(self, file_path: str) -> list[Fact]:
        results = []
        if not file_path.endswith('shadycompass.ini'):
            return results
        global0 = os.path.realpath(file_path) == os.path.realpath(get_global_config_path())
        config = ConfigParser()
        config.read(file_path)
        for section in config.sections():
            for option in config.options(section):
                value = config.get(section, option)
                results.append(
                    ConfigFact(section=section, option=option, value=value, global0=global0))

        return results


fact_reader_registry.append(ConfigFactReader())


class PreferredTool(Fact):
    category = Field(str, mandatory=True)
    name = Field(str, mandatory=True)


class ToolChoiceNeeded(Fact):
    category = Field(str, mandatory=True)
    names = Field(list[str], mandatory=True)


class ToolRecommended(Fact):
    category = Field(str, mandatory=True)
    name = Field(str, mandatory=True)
    """ The name of the tool as run from the command line. """
    variation = Field(str, mandatory=False)
    """ If a tool is recommended multiple times, provide a variant to identify it. Not shown to the user."""
    command_line = Field(list[str], mandatory=False)
    """ Command line to run without the tool name. """
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=False)
    hostname = Field(str, mandatory=False)

    def get_category(self) -> str:
        return self.get('category')

    def get_name(self) -> str:
        return self.get('name')

    def get_variation(self) -> str:
        return self.get('variation')

    def get_command_line(self) -> list[str]:
        if 'command_line' in self:
            return self.get('command_line')
        return []

    def get_addr(self) -> str:
        return self.get('addr')

    def get_port(self) -> Union[int, None]:
        if 'port' in self:
            return int(self.get('port'))
        return None

    def get_hostname(self) -> str:
        return self.get('hostname')


class ConfigRules(IRules, ABC):
    def _get_tools(self, category: str) -> list[ToolAvailable]:
        tools = []
        for fact in self.facts.values():
            if isinstance(fact, ToolAvailable) and fact.get('category') == category:
                tools.append(fact)
        return tools

    def _declare_preferred_tool(self, category: str, tool_name: str):
        retract_queue = []
        for fact in filter(
                lambda f: isinstance(f, PreferredTool) and f.get('category') == category and f.get('name') != tool_name,
                           self.facts.values()):
            retract_queue.append(fact)
        for fact in retract_queue:
            self.retract(fact)
        self.declare(PreferredTool(category=category, name=tool_name))

    @Rule(
        ConfigFact(section=SECTION_TOOLS, option=MATCH.category, value=MATCH.tool_name, global0=False),
        salience=100
    )
    def preferred_tool_local(self, category, tool_name):
        self._declare_preferred_tool(category, tool_name)

    @Rule(
        ConfigFact(section=SECTION_TOOLS, option=MATCH.category, value=MATCH.tool_name, global0=True),
        NOT(PreferredTool(category=MATCH.category)),
    )
    def preferred_tool_global(self, category, tool_name):
        self._declare_preferred_tool(category, tool_name)

    @Rule(
        ToolAvailable(category=MATCH.category),
        NOT(PreferredTool(category=MATCH.category)),
    )
    def choose_tool(self, category):
        tool_names = list(map(lambda t: t.get('name'), self._get_tools(category)))
        if len(tool_names) == 1:
            self._declare_preferred_tool(category, tool_names[0])
        else:
            self.declare(ToolChoiceNeeded(category=category, names=tool_names))

    @Rule(
        PreferredTool(category=MATCH.category),
        AS.f1 << ToolChoiceNeeded(category=MATCH.category)
    )
    def tool_chosen(self, f1):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=MATCH.category, name=MATCH.name),
        PreferredTool(category=MATCH.category, name=~MATCH.name),
        NOT(PreferredTool(category=MATCH.category, name=OPTION_VALUE_ALL)),
    )
    def retract_tool(self, f1):
        self.retract(f1)

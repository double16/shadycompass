import os
from configparser import ConfigParser
from typing import Union

from experta import Fact, Field, Rule, AS, MATCH, NOT

from shadycompass.facts import FactReader, fact_reader_registry

SECTION_TOOLS = 'tools'
OPTION_VALUE_ALL = '*'


class ToolCategory(object):
    port_scanner = 'port_scanner'
    http_buster = 'http_buster'
    vuln_scanner = 'vuln_scanner'


class ToolAvailable(Fact):
    category = Field(str, mandatory=True)
    name = Field(str, mandatory=True)
    tool_link = Field(str, mandatory=False)
    doc_links = Field(list[str], mandatory=False)


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
    command_line = Field(list[str], mandatory=False)

    def get_category(self) -> str:
        return self.get('category')

    def get_name(self) -> str:
        return self.get('name')

    def get_command_line(self) -> list[str]:
        if 'command_line' in self:
            return self.get('command_line')
        return []


class ConfigRules:
    def _get_tools(self, category: str) -> list[ToolAvailable]:
        tools = []
        for fact in self.facts.values():
            if isinstance(fact, ToolAvailable) and fact.get('category') == category:
                tools.append(fact)
        return tools

    @Rule(
        ConfigFact(section=SECTION_TOOLS, option=MATCH.category, value=MATCH.tool_name, global0=False),
        salience=100
    )
    def preferred_tool_local(self, category, tool_name):
        self.declare(PreferredTool(category=category, name=tool_name))

    @Rule(
        ConfigFact(section=SECTION_TOOLS, option=MATCH.category, value=MATCH.tool_name, global0=True),
        NOT(PreferredTool(category=MATCH.category)),
    )
    def preferred_tool_global(self, category, tool_name):
        self.declare(PreferredTool(category=category, name=tool_name))

    @Rule(
        ToolAvailable(category=MATCH.category),
        NOT(PreferredTool(category=MATCH.category)),
    )
    def choose_tool(self, category):
        tool_names = list(map(lambda t: t.get('name'), self._get_tools(category)))
        if len(tool_names) == 1:
            self.declare(PreferredTool(category=category, name=tool_names[0]))
        else:
            self.declare(ToolChoiceNeeded(category=category, names=tool_names))

    @Rule(
        PreferredTool(category=MATCH.category),
        AS.f1 << ToolChoiceNeeded(category=MATCH.category)
    )
    def tool_chosen(self, f1):
        self.retract(f1)

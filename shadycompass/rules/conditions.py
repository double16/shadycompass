from experta import OR, NOT

from shadycompass.config import PreferredTool, OPTION_VALUE_ALL, SECTION_OPTIONS, ConfigFact


def TOOL_PREF(category: str, tool_name: str):
    return OR(
        PreferredTool(category=category, name=tool_name),
        PreferredTool(category=category, name=OPTION_VALUE_ALL),
        NOT(PreferredTool(category=category)),
    )


def TOOL_CONF(category: str, tool_name: str):
    return OR(ConfigFact(section=SECTION_OPTIONS, option=tool_name),
              NOT(ConfigFact(section=SECTION_OPTIONS, option=tool_name)))

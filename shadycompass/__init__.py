import io
import os.path
import shlex
import sys
from configparser import ConfigParser

from experta import KnowledgeEngine

import shadycompass.facts.all  # noqa: F401
from shadycompass.config import ConfigFact, get_local_config_path, \
    get_global_config_path, ToolChoiceNeeded, SECTION_TOOLS, OPTION_VALUE_ALL, ToolRecommended, ToolAvailable, \
    set_local_config_path
from shadycompass.facts import fact_reader_registry
from shadycompass.facts.filemetadata import FileMetadataCache
from shadycompass.rules.all import AllRules


class ShadyCompassEngine(
    KnowledgeEngine,
    AllRules,
):
    def __init__(self, paths: list[str] = None):
        super().__init__()
        if paths is None:
            paths = [os.getcwd()]
        for fact_reader in fact_reader_registry:
            paths.extend(fact_reader.files())
        self.file_metadata = FileMetadataCache(paths)

    def update_facts(self):
        retract_queue = []
        for file_path in self.file_metadata.find_changes():
            if os.path.exists(file_path):
                for fact_reader in fact_reader_registry:
                    the_facts = fact_reader.read_facts(file_path)
                    for the_fact in the_facts:
                        the_fact.update({'file_path': file_path})
                        self.declare(the_fact)
            else:
                # retract facts for files that have been removed
                for fact in self.facts.values():
                    if fact.get('file_path') == file_path:
                        retract_queue.append(fact)
        for fact in retract_queue:
            self.retract(fact)

    def _save_config(self, facts: list[ConfigFact], config_path: str):
        config = ConfigParser()
        for fact in facts:
            section = str(fact.get('section'))
            if not config.has_section(section):
                config.add_section(section)
            config.set(section, str(fact.get('option')), str(fact.get('value')))
        with open(config_path, 'w') as file:
            config.write(file)

    def save_config(self):
        local_configs = list()
        global_configs = list()
        for fact in filter(lambda f: isinstance(f, ConfigFact), self.facts.values()):
            if fact.get('global0'):
                global_configs.append(fact)
            else:
                local_configs.append(fact)
        self._save_config(local_configs, get_local_config_path())
        self._save_config(global_configs, get_global_config_path())


class ShadyCompassOps(object):
    def __init__(self, args: list[str], fd_in=sys.stdin, fd_out=sys.stdout, fd_err=sys.stderr):
        self.fd_in = fd_in
        self.fd_out = fd_out
        self.fd_err = fd_err
        self.base_dir = os.getcwd() if len(args) == 0 else args[0]
        set_local_config_path(os.path.join(self.base_dir, 'shadycompass.ini'))
        self.engine = ShadyCompassEngine([self.base_dir])
        self.engine.reset()

    def handle_tool_choices(self) -> bool:
        changed = False
        for tool_choice in list(filter(lambda f: isinstance(f, ToolChoiceNeeded), self.engine.facts.values())):
            category: str = tool_choice.get('category')
            names: list[str] = list(tool_choice.get('names'))
            names.sort()
            if len(names) == 1:
                self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=category, value=names[0], global0=False))
                self.engine.retract(tool_choice)
                changed = True
                continue

            while True:
                print(f"\nChoose your preferred tool for {category}:", file=self.fd_out)
                for idx, name in enumerate(names):
                    print(f"{idx+1}. {name}")
                print("0. no preference, consider all", file=self.fd_out)
                try:
                    choice = int(input("? ").strip()) - 1
                    if -1 <= choice < len(names):
                        self.engine.declare(ConfigFact(
                            section=SECTION_TOOLS,
                            option=category,
                            value=OPTION_VALUE_ALL if choice < 0 else names[choice],
                            global0=False))
                        self.engine.retract(tool_choice)
                        changed = True
                        break
                except (EOFError, KeyboardInterrupt) as e:
                    raise e
                except Exception as e:
                    print(e)
        if changed:
            self.print_save_config_warning()
        return changed

    def _command_line(self, args: list[str]) -> str:
        return shlex.join(args)

    def handle_tool_recommended(self):
        for idx, tool in enumerate(list(filter(lambda f: isinstance(f, ToolRecommended), self.engine.facts.values()))):
            print(f"[$] {str(idx + 1).rjust(2, ' ')}. {tool.get_name()} {self._command_line(tool.get_command_line())}",
                  file=self.fd_out)

    def tool_info(self, command: list[str]):
        recommends = list(filter(lambda f: isinstance(f, ToolRecommended), self.engine.facts.values()))
        tools = {}
        for fact in filter(lambda f: isinstance(f, ToolAvailable), self.engine.facts.values()):
            tools[fact.get('name')] = fact
        for arg in command[1:]:
            try:
                i = int(arg) - 1
                if 0 <= i < len(recommends):
                    tr: ToolRecommended = recommends[i]
                    ta: ToolAvailable = tools[tr.get_name()]
                    print(f'\n# {ta.get_name()}', file=self.fd_out)
                    if ta.get_tool_links():
                        print('\n## tool links')
                        print('\n'.join(ta.get_tool_links()), file=self.fd_out)
                    if ta.get_methodology_links():
                        print('\n## methodology')
                        print('\n'.join(ta.get_methodology_links()), file=self.fd_out)
                    print('\n## example command\n```shell')
                    print(tr.get_name() + ' ' + self._command_line(tr.get_command_line()), file=self.fd_out)
                    print('```')
                else:
                    print(f'[-] invalid number, expecting 1-{len(recommends)}', file=self.fd_out)
            except ValueError:
                print(f'[-] number expected: {arg}', file=self.fd_out)

    def print_banner(self):
        print("""
shadycompass - https://github.com/double16/shadycompass
Press enter/return at the prompt to refresh data.
""", file=self.fd_out)

    def refresh(self):
        self.engine.update_facts()
        self.engine.run()

    def print_save_config_warning(self):
        print('[!] configuration is only saved when you run the "save" command', file=self.fd_out)

    def save_config(self):
        # TODO: save on config fact declaration
        self.engine.save_config()
        print('[*] config saved', file=self.fd_out)

    def use_tool(self, command: list[str]):
        """
        # choose a tool across all categories, optionally reset options: use [global] feroxbuster [--reset-options]
        :param command:
        :return:
        """
        global0 = False
        tool_name = None
        reset_options = False
        for arg in command[1:]:
            if arg == 'global':
                global0 = True
            elif arg == '--reset-options':
                reset_options = True
                print('[!] Submit a PR for --reset-options :)', file=self.fd_err)
            elif arg.startswith('-'):
                raise ValueError(arg)
            elif tool_name is not None:
                raise ValueError(arg)
            else:
                tool_name = arg
        category = []
        for fact in filter(lambda f: isinstance(f, ToolAvailable), self.engine.facts.values()):
            if fact.get('name') == tool_name:
                category.append(fact.get('category'))
        if len(category) == 0:
            raise ValueError(f"{tool_name} not found")
        for cat in category:
            self.engine.declare(ConfigFact(section=SECTION_TOOLS, option=cat, value=tool_name, global0=global0))
            print(f'[*] using {tool_name} for {cat}', file=self.fd_out)
        self.print_save_config_warning()

    def tool_option(self, command: list[str]):
        # TODO: adds option(s) to a tool, i.e.: option feroxbuster --scan-limit 4
        # TODO: [global]
        print('[!] Submit a PR :)', file=self.fd_err)

    def show_config(self):
        config = ConfigParser()
        for fact in filter(lambda f: isinstance(f, ConfigFact), self.engine.facts.values()):
            section = str(fact.get('section'))
            if not config.has_section(section):
                config.add_section(section)
            value = str(fact.get('value'))
            if fact.get('global0'):
                value += "  # global"
            config.set(section, str(fact.get('option')), value)

        with io.StringIO() as buffer:
            config.write(buffer)
            config_string = '\n'+buffer.getvalue()

        print(config_string, file=self.fd_out)

    def set_config_value(self, command: list[str]):
        """
        set [global] [section.]option value
        """
        global0 = False
        section = None
        option = None
        value = None
        for arg in command[1:]:
            if arg == 'global':
                global0 = True
            elif arg.startswith('-'):
                raise ValueError(arg)
            elif option is None:
                if '.' in arg:
                    split = arg.split('.', 1)
                    section = split[0]
                    option = split[1]
                else:
                    section = 'general'
                    option = arg
            elif value is None:
                value = arg
            else:
                raise ValueError(arg)
        self.engine.declare(ConfigFact(section=section, option=option, value=value, global0=global0))
        self.print_save_config_warning()

    def unset_config_value(self, command: list[str]):
        """
        set [global] [section.]option value
        """
        global0 = False
        section = None
        option = None
        for arg in command[1:]:
            if arg == 'global':
                global0 = True
            elif arg.startswith('-'):
                raise ValueError(arg)
            elif option is None:
                if '.' in arg:
                    split = arg.split('.', 1)
                    section = split[0]
                    option = split[1]
                else:
                    section = 'general'
                    option = arg
            else:
                raise ValueError(arg)
        retract_queue = []
        for fact in filter(lambda f: isinstance(f, ConfigFact), self.engine.facts.values()):
            if fact.get('section') == section and fact.get('option') == option and bool(fact.get('global0')) == global0:
                retract_queue.append(fact)
        for fact in retract_queue:
            self.engine.retract(fact)
        self.print_save_config_warning()

    def reset_config_values(self):
        """
        Reset all config values.
        """
        configs = [fact for fact in filter(lambda f: isinstance(f, ConfigFact), self.engine.facts.values())]
        for fact in configs:
            self.engine.retract(fact)
        self.print_save_config_warning()

import io
import os.path
import random
import re
import shlex
import sys
from configparser import ConfigParser
from typing import Union

from experta import KnowledgeEngine, Fact

import shadycompass.facts.all  # noqa: F401
from shadycompass.config import ConfigFact, get_local_config_path, \
    get_global_config_path, ToolChoiceNeeded, SECTION_TOOLS, OPTION_VALUE_ALL, ToolRecommended, ToolAvailable, \
    set_local_config_path, SECTION_OPTIONS, combine_command_options, tool_category_priority
from shadycompass.facts import fact_reader_registry, TargetIPv4Address, TargetIPv6Address, HostnameIPv6Resolution, \
    HostnameIPv4Resolution, TargetHostname, TcpIpService, UdpIpService, Product, HttpUrl, HasTLS, TargetDomain
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

    def config_set(self, section: str, option: str, value: str, global0: bool):
        self.config_unset(section, option, global0)
        self.declare(ConfigFact(section=section, option=option, value=value, global0=global0))

    def config_unset(self, section: str, option: str, global0: bool):
        existing = None
        for fact in self.facts.values():
            if isinstance(fact, ConfigFact) and fact.get('section') == section and fact.get(
                    'option') == option and fact.get('global0') == global0:
                existing = fact
                break
        if existing:
            self.retract(existing)

    def config_get(self, section: str, option: str, global0: bool):
        for fact in self.facts.values():
            if isinstance(fact, ConfigFact) and fact.get('section') == section and fact.get(
                    'option') == option and fact.get('global0') == global0:
                return fact.get('value')
        return None

    def config_get_fallback(self, section: str, option: str, default_value: Union[str, None] = None) -> str:
        value = self.config_get(section, option, False)
        if not value:
            value = self.config_get(section, option, True)
        return default_value if value is None else value

    def resolve_command_line(self, tool_name: str, options: list[str], *args) -> list[str]:
        additional_str = self.config_get_fallback(SECTION_OPTIONS, tool_name)
        if additional_str:
            additional = shlex.split(additional_str)
        else:
            additional = []
        return combine_command_options(options, additional, *args)

    def get_matches(self, query: Fact) -> list[Fact]:
        """ Get facts that have attributes equal to those specified in the query. """

        def _is_match(fact: Fact, f1: Fact) -> bool:
            if type(fact) != type(f1):
                return False
            for k, v in fact.items():
                v1 = f1.get(k)
                if repr(v) != repr(v1):
                    return False
            return True

        result: list[Fact] = []
        for f1 in self.facts.values():
            if _is_match(query, f1):
                result.append(f1)
        return result

    def recommend_tool(self,
                       category: str,
                       name: str,
                       variant: str,
                       command_line: list[str],
                       addr: Union[str, None] = None,
                       hostname: Union[str, None] = None,
                       port: Union[int, None] = None):
        query = {'category': category, 'name': name}
        if variant is not None:
            query['variant'] = variant
        if addr is not None:
            query['addr'] = addr
        if port is not None:
            query['port'] = port
        if hostname is not None:
            query['hostname'] = hostname
        existing = self.get_matches(ToolRecommended(**query))
        if existing:
            for fact in existing:
                self.modify(fact, command_line=command_line)
        else:
            self.declare(ToolRecommended(command_line=command_line, **query))


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
                except KeyboardInterrupt as e:
                    raise e
                except EOFError:
                    print("0")
                    choice = -1
                try:
                    if -1 <= choice < len(names):
                        self.engine.declare(ConfigFact(
                            section=SECTION_TOOLS,
                            option=category,
                            value=OPTION_VALUE_ALL if choice < 0 else names[choice],
                            global0=True))
                        self.engine.retract(tool_choice)
                        changed = True
                        break
                except Exception as e:
                    print(e)
        if changed:
            self.print_save_config_warning()
        return changed

    def _command_line(self, args: list[str]) -> str:
        return shlex.join(args)

    def _find_tool_recommended(self) -> list[ToolRecommended]:
        facts = list(filter(lambda f: isinstance(f, ToolRecommended), self.engine.facts.values()))
        facts.sort(key=lambda e: [-tool_category_priority(e.get('category')), e.get('name')])
        return facts

    def handle_tool_recommended(self):
        for idx, tool in enumerate(self._find_tool_recommended()):
            print(f"[$] {str(idx + 1).rjust(2, ' ')}. {tool.get_name()} {self._command_line(tool.get_command_line())}",
                  file=self.fd_out)

    def tool_info(self, command: list[str]):
        recommends = self._find_tool_recommended()
        tools = {}
        for fact in filter(lambda f: isinstance(f, ToolAvailable), self.engine.facts.values()):
            tools[fact.get('name')] = fact
        for arg in command[1:]:
            tr: Union[ToolRecommended, None] = None
            ta: Union[ToolAvailable, None]
            try:
                i = int(arg) - 1
                if 0 <= i < len(recommends):
                    tr = recommends[i]
                    ta = tools.get(tr.get_name(), None)
                else:
                    print(f'[-] invalid number, expecting 1-{len(recommends)}', file=self.fd_out)
                    continue
            except ValueError:
                if arg.lower() in tools:
                    ta = tools[arg]
                else:
                    print(f'[-] unknown tool: {arg}', file=self.fd_out)
                    continue
            if ta:
                print(f'\n# {ta.get_name()}', file=self.fd_out)
                if ta.get_tool_links():
                    print('\n## tool links')
                    print('\n'.join(ta.get_tool_links()), file=self.fd_out)
                if ta.get_methodology_links():
                    print('\n## methodology')
                    print('\n'.join(ta.get_methodology_links()), file=self.fd_out)
            if tr:
                print('\n## example command\n```shell')
                print(tr.get_name() + ' ' + self._command_line(tr.get_command_line()), file=self.fd_out)
                print('```')

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
            self.engine.config_set(SECTION_TOOLS, cat, tool_name, global0)
            if reset_options:
                self.engine.config_unset(SECTION_OPTIONS, tool_name, global0)
            print(f'[*] using {tool_name} for {cat}', file=self.fd_out)
        self.print_save_config_warning()

    def tool_option(self, command: list[str]):
        global0 = False
        tool_name = None
        options = []
        for arg in command[1:]:
            if arg == 'global' and tool_name is None:
                global0 = True
            elif tool_name is None:
                if arg.startswith('-'):
                    raise ValueError(arg)
                tool_name = arg
            else:
                options.append(arg)
        existing_str = self.engine.config_get(SECTION_OPTIONS, tool_name, global0)
        if existing_str:
            existing = shlex.split(existing_str)
        else:
            existing = []
        new_options = combine_command_options(existing, options)
        existing.extend(options)
        self.engine.config_set(SECTION_OPTIONS, tool_name, shlex.join(new_options), global0)

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

    def global_thermo_nuclear_war(self):
        if random.randint(0, 100) < 30:
            print("\nA strange game. The only winning move is not to play.", file=self.fd_out)
        else:
            print("\nWouldn't you prefer a nice game of chess?", file=self.fd_out)

    def show_tools(self, command: list[str]):
        tools_by_category: dict[str, list[ToolAvailable]] = dict()
        for fact in filter(lambda f: isinstance(f, ToolAvailable), self.engine.facts.values()):
            tool: ToolAvailable = fact
            if tool.get_category() not in tools_by_category:
                tools_by_category[tool.get_category()] = list()
            tool_list = tools_by_category[tool.get_category()]
            tool_list.append(tool)
        categories = list(tools_by_category.keys())
        categories.sort(key=lambda e: tool_category_priority(e), reverse=True)
        for category in categories:
            print(f'\n# {category}', file=self.fd_out)
            tools_by_category[category].sort(key=lambda ta: ta.get_name())
            for tool in tools_by_category[category]:
                print(f' - {tool.get_name()}', file=self.fd_out)

    def show_targets(self, command: list[str]):
        addr_targets: set[str] = set()
        hostname_targets: set[str] = set()
        domains: set[str] = set()
        resolved: list[tuple[str, str]] = []
        for fact in self.engine.facts.values():
            if isinstance(fact, TargetIPv4Address):
                addr_targets.add(fact.get_addr())
            elif isinstance(fact, TargetIPv6Address):
                addr_targets.add(fact.get_addr())
            elif isinstance(fact, TargetHostname):
                hostname_targets.add(fact.get_hostname())
            elif isinstance(fact, TargetDomain):
                domains.add(fact.get_domain())
            elif isinstance(fact, HostnameIPv4Resolution):
                resolved.append((fact.get_addr(), fact.get_hostname()))
            elif isinstance(fact, HostnameIPv6Resolution):
                resolved.append((fact.get_addr(), fact.get_hostname()))
        print('', file=self.fd_out)
        for addr, hostname in resolved:
            if addr in addr_targets or hostname in hostname_targets:
                print(f' - {addr} {hostname}', file=self.fd_out)
                try:
                    addr_targets.remove(addr)
                except KeyError:
                    pass
                try:
                    hostname_targets.remove(hostname)
                except KeyError:
                    pass
        for addr in addr_targets:
            print(f' - {addr}', file=self.fd_out)
        for hostname in hostname_targets:
            print(f' - {hostname}', file=self.fd_out)
        for domain in domains:
            if '.' in domain:
                wildcard = '*.'
            else:
                wildcard = ''
            print(f' - {wildcard}{domain}', file=self.fd_out)

    def show_services(self, command: list[str]):

        demangle_pattern = re.compile('([a-z0-9])([A-Z])')

        def demangle(camel_case: str) -> str:
            result = camel_case.replace('Service', '')
            result = demangle_pattern.sub(lambda m: m.group(1) + ' ' + m.group(2).lower(), result).lower()
            return result

        services_by_addr: dict[str, set] = dict()
        for fact in self.engine.facts.values():
            if isinstance(fact, TcpIpService) or isinstance(fact, UdpIpService):
                addr = fact.get('addr')
                if addr not in services_by_addr:
                    services_by_addr[addr] = set()
                services_by_addr[addr].add(fact)

        print('', file=self.fd_out)
        for addr, services in services_by_addr.items():
            print(f'# {addr}', file=self.fd_out)
            sorted_services = list(services)
            sorted_services.sort(key=lambda e: int(e.get('port')))
            for fact in sorted_services:
                secure_text = ''
                if isinstance(fact, HasTLS) and fact.is_secure():
                    secure_text = '/ssl'
                link_text = ''
                if 'methodology_links' in fact.__class__.__dict__:
                    links = fact.__class__.__dict__['methodology_links']
                    if links:
                        link_text = ', ' + ', '.join(links)
                if isinstance(fact, TcpIpService):
                    print(f'- {fact.get_port()}/tcp {demangle(fact.__class__.__name__)}{secure_text}{link_text}',
                          file=self.fd_out)
                if isinstance(fact, UdpIpService):
                    print(f'- {fact.get_port()}/udp {demangle(fact.__class__.__name__)}{secure_text}{link_text}',
                          file=self.fd_out)

    def show_products(self, command: list[str]):
        products_by_service: dict[str, set[str]] = dict()
        for fact in filter(lambda f: isinstance(f, Product), self.engine.facts.values()):
            key = f'{fact.get_addr()}:{fact.get_port()}'
            if key not in products_by_service:
                products_by_service[key] = set()
            products_by_service[key].add(fact.get_product_spec())
        print('', file=self.fd_out)
        for service, products in products_by_service.items():
            print(f'# {service}', file=self.fd_out)
            for product in products:
                print(f' - {product}', file=self.fd_out)

    def show_urls(self, command: list[str]):
        print('', file=self.fd_out)
        for fact in filter(lambda f: isinstance(f, HttpUrl), self.engine.facts.values()):
            print(f'- {fact.get_url()}', file=self.fd_out)

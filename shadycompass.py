#!/usr/bin/env python3
import argparse
import shlex
import sys

from prompt_toolkit import prompt
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import InMemoryHistory

from shadycompass import ShadyCompassOps, get_local_config_path, get_global_config_path, ToolAvailable
from shadycompass.config import OPTION_RATELIMIT, OPTION_PRODUCTION, SECTION_WORDLISTS, OPTION_WORDLIST_FILE, \
    OPTION_WORDLIST_USERNAME, OPTION_WORDLIST_PASSWORD, OPTION_WORDLIST_SUBDOMAIN


def shadycompass_cli(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog='shadycompass',
        description='Tool to help ethical hackers cover enumeration steps.')
    parser.add_argument('directories', metavar='dir', type=str, nargs='+',
                        help='directory to search for tool output')
    parsed = parser.parse_args(args)

    # history = FileHistory(os.path.join(os.path.dirname(get_global_config_path()), 'history.txt'))
    history = InMemoryHistory()
    ops = ShadyCompassOps(parsed.directories)
    commands = ['exit', 'quit', 'save', 'use', 'option', 'set', 'unset', 'reset', 'info', 'facts', 'tools', 'targets',
                'services', 'products', 'urls', 'users', 'emails', 'reload']
    config_names = {
        OPTION_RATELIMIT, OPTION_PRODUCTION,
        SECTION_WORDLISTS + '.' + OPTION_WORDLIST_FILE, SECTION_WORDLISTS + '.' + OPTION_WORDLIST_SUBDOMAIN,
        SECTION_WORDLISTS + '.' + OPTION_WORDLIST_USERNAME, SECTION_WORDLISTS + '.' + OPTION_WORDLIST_PASSWORD,
    }
    config_dict = {name: None for name in config_names}
    tools = set(map(lambda e: e.get_name(), filter(lambda e: isinstance(e, ToolAvailable), ops.engine.facts.values())))
    tools_dict = {tool: None for tool in tools}
    completer = NestedCompleter.from_nested_dict({
        **{command:None for command in commands},
        'use': {
            'global': tools,
            **tools_dict,
        },
        'option': {
            'global': tools,
            **tools_dict,
        },
        'info': tools,
        'set': {
            'global': config_names,
            **config_dict,
        },
        'unset': {
            'global': config_names,
            **config_dict,
        },
    })

    try:
        ops.print_banner()
        while True:
            ops.refresh()

            if ops.handle_tool_choices():
                continue

            print('')

            ops.handle_tool_recommended()

            while True:
                prompt_text = f"\n{ops.base_dir} shadycompass > "
                if sys.stdout.isatty():
                    user_input = prompt(prompt_text,
                                       history=history,
                                       auto_suggest=AutoSuggestFromHistory(),
                                       completer=completer,
                                        )
                else:
                    user_input = input(prompt_text)

                user_command = shlex.split(user_input)

                if len(user_command) == 0:
                    break

                if user_command[0] in ['exit', 'quit', 'x', 'q']:
                    return 0

                elif user_command[0] == 'facts':
                    if len(user_command) > 1:
                        facts = list(filter(lambda e: user_command[1].lower() in str(type(e)).lower(),
                                            ops.engine.facts.values()))
                    else:
                        facts = ops.engine.facts.values()
                    print('\n'.join(map(repr, facts)))
                elif user_command[0] == 'save':
                    ops.save_config()
                elif user_command[0] == 'use':
                    ops.use_tool(user_command)
                    break
                elif user_command[0] == 'option':
                    ops.tool_option(user_command)
                    break
                elif user_command == ['set']:
                    ops.show_config()
                elif user_command[0] == 'set':
                    ops.set_config_value(user_command)
                    break
                elif user_command[0] == 'unset':
                    ops.unset_config_value(user_command)
                    break
                elif user_command[0] == 'reset':
                    ops.reset_config_values()
                    break
                elif user_command[0] == 'info':
                    ops.tool_info(user_command)
                elif user_command[0] == 'globalthermonuclearwar':
                    ops.global_thermo_nuclear_war()
                elif user_command[0] == 'tools':
                    ops.show_tools(user_command)
                elif user_command[0] == 'targets':
                    ops.show_targets(user_command)
                elif user_command[0] == 'services':
                    ops.show_services(user_command)
                elif user_command[0] == 'products':
                    ops.show_products(user_command)
                elif user_command[0] == 'urls':
                    ops.show_urls(user_command)
                elif user_command[0] == 'users':
                    ops.show_users(user_command)
                elif user_command[0] == 'emails':
                    ops.show_emails(user_command)
                elif user_command[0] == 'reload':
                    ops.reload()
                    break

                else:
                    print(f'''
help
    show this text
exit, quit, x, q
    quit, eh?
info <n or name> [ ... ]
    show information on a recommendation, multiple numbers (separated by whitespace) accepted or tool names
save
    save configuration changes to {get_local_config_path()} (local) and {get_global_config_path()} (global) 
use [global] <tool> [--reset-options]
    prefer a tool over others in the same category
option [global] <tool> args ...
    add options to a tool
set
    show configuration
set [global] [section.]option value
    set a configuration, section defaults to 'general'
    * don't forget to run 'save' to persist
unset [global] [section.]option
    section defaults to 'general'
    * don't forget to run 'save' to persist
reset
    reset/unset all configurations, including global
    * don't forget to run 'save' to persist
tools
    displays the available tools
targets
    displays the targets that have been found
services
    displays the services that have been found
products
    displays the products that have been found
urls
    displays the urls that have been found
users
    displays the users that have been found
emails
    displays the emails that have been found
reload
    reload from all files, only needed if recommendations aren't updated properly
facts
    show current facts (useful for debugging)
''')

    except (EOFError, KeyboardInterrupt):
        # normal exit
        pass

    return 0


if __name__ == '__main__':
    sys.exit(shadycompass_cli(sys.argv[1:]))

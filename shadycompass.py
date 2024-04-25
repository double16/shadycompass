#!/usr/bin/env python3
import os
import sys

from shadycompass import ShadyCompassEngine
from shadycompass.config import ToolChoiceNeeded, ConfigFact, SECTION_TOOLS, \
    OPTION_VALUE_ALL, ToolRecommended


def handle_tool_choices(engine: ShadyCompassEngine) -> bool:
    changed = False
    for tool_choice in list(filter(lambda f: isinstance(f, ToolChoiceNeeded), engine.facts.values())):
        category: str = tool_choice.get('category')
        names: list[str] = tool_choice.get('names')
        if len(names) == 1:
            engine.declare(ConfigFact(section=SECTION_TOOLS, option=category, value=names[0], global0=False))
            engine.retract(tool_choice)
            changed = True
            continue

        while True:
            print(f"\nChoose your preferred tool for {category}:")
            for idx, name in enumerate(names):
                print(f"{idx+1}. {name}")
            print(f"{len(names)+1}. no preference, consider all")
            try:
                choice = int(input("? ").strip()) - 1
                if 0 <= choice <= len(names):
                    engine.declare(ConfigFact(
                        section=SECTION_TOOLS,
                        option=category,
                        value=OPTION_VALUE_ALL if choice == len(names) else names[choice-1],
                        global0=False))
                    engine.retract(tool_choice)
                    changed = True
                    break
            except EOFError:
                sys.exit(0)
            except KeyboardInterrupt:
                sys.exit(130)
            except Exception as e:
                print(e)
    return changed


def handle_tool_recommended(engine: ShadyCompassEngine) -> bool:
    for tool in list(filter(lambda f: isinstance(f, ToolRecommended), engine.facts.values())):
        print(f"[$] {tool.get_name()} {' '.join(tool.get_command_line())}")


def print_banner():
    print("\nshadycompass - https://github.com/double16/shadycompass")
    print("\nPress enter/return at the prompt to refresh data.\n")


def shadycompass_cli(args: list[str]) -> int:
    base_dir = os.getcwd() if len(args) == 0 else args[0]
    engine = ShadyCompassEngine([base_dir])
    engine.reset()
    try:
        print_banner()
        while True:
            engine.update_facts()
            engine.run()

            if handle_tool_choices(engine):
                continue

            handle_tool_recommended(engine)

            user_command = input(f"\n{base_dir} shadycompass > ")

            if user_command == 'help':
                print('''
help
facts
save
use [global] <tool> [--reset]
option [global] <tool> args ...
set
set [global] name value
unset [global] name
reset [global]
exit, quit, x, q
''')

            if user_command in ['exit', 'quit', 'x', 'q']:
                return 0

            if user_command == 'facts':
                print(engine.facts)

            if user_command == 'save':
                # TODO: save on config fact declaration
                engine.save_config()
                print('[*] config saved')

            if user_command.startswith('use '):
                # TODO: choose a tool across all categories, optionally reset options: use feroxbuster [--reset]
                # TODO: [global]
                pass

            if user_command.startswith('option '):
                # TODO: adds option(s) to a tool, i.e.: option feroxbuster --scan-limit 4
                # TODO: [global]
                pass

            if user_command in ['set', 'unset']:
                # TODO: show config values, indicate global/local
                pass

            if user_command.startswith('set '):
                # TODO: set a config value i.e.: set ratelimit 5
                # TODO: [global]
                pass

            if user_command.startswith('unset '):
                # TODO: unset a config value i.e.: unset ratelimit
                # TODO: [global]
                pass

            if user_command == 'reset':
                # TODO: unset all configs
                # TODO: [global]
                pass

    except (EOFError, KeyboardInterrupt):
        # normal exit
        pass

    return 0


if __name__ == '__main__':
    sys.exit(shadycompass_cli(sys.argv[1:]))

#!/usr/bin/env python3
import sys
import shlex


from shadycompass import ShadyCompassOps

def shadycompass_cli(args: list[str]) -> int:
    ops = ShadyCompassOps(args)
    try:
        ops.print_banner()
        while True:
            ops.refresh()

            if ops.handle_tool_choices():
                continue

            ops.handle_tool_recommended()

            user_command = shlex.split(input(f"\n{ops.base_dir} shadycompass > "))

            if len(user_command) == 0:
                continue

            if user_command[0] in ['exit', 'quit', 'x', 'q']:
                return 0

            elif user_command[0] == 'facts':
                print(ops.engine.facts)

            elif user_command[0] == 'save':
                ops.save_config()

            elif user_command[0] == 'use':
                ops.use_tool(user_command)

            elif user_command[0] == 'option':
                ops.tool_option(user_command)

            elif user_command == ['set']:
                ops.show_config()

            elif user_command[0] == 'set':
                ops.set_config_value(user_command)

            elif user_command[0] == 'unset':
                ops.unset_config_value(user_command)

            elif user_command[0] == 'reset':
                ops.reset_config_values()

            else:
                print('''
help
facts
save
use [global] <tool> [--reset-options]
option [global] <tool> args ...
set
set [global] [section.]option value  (section defaults to 'general')
unset [global] [section.]option  (section defaults to 'general')
reset
exit, quit, x, q
''')

    except (EOFError, KeyboardInterrupt):
        # normal exit
        pass

    return 0


if __name__ == '__main__':
    sys.exit(shadycompass_cli(sys.argv[1:]))

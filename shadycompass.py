#!/usr/bin/env python3
import sys
import shlex


from shadycompass import ShadyCompassOps, get_local_config_path, get_global_config_path


def shadycompass_cli(args: list[str]) -> int:
    ops = ShadyCompassOps(args)
    try:
        ops.print_banner()
        while True:
            ops.refresh()

            if ops.handle_tool_choices():
                continue

            print('')

            ops.handle_tool_recommended()

            while True:
                user_command = shlex.split(input(f"\n{ops.base_dir} shadycompass > "))

                if len(user_command) == 0:
                    break

                if user_command[0] in ['exit', 'quit', 'x', 'q']:
                    return 0

                elif user_command[0] == 'facts':
                    print(ops.engine.facts)
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

                else:
                    print(f'''
help
    show this text
exit, quit, x, q
    quit, eh?
info n [ ... ]
    show information on a recommendation, multiple numbers (separated by whitespace) accepted
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
facts
    show current facts (useful for debugging)
''')

    except (EOFError, KeyboardInterrupt):
        # normal exit
        pass

    return 0


if __name__ == '__main__':
    sys.exit(shadycompass_cli(sys.argv[1:]))

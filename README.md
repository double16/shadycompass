# shadycompass

Shady Compass is a tool to help ethical hackers cover enumeration steps. It looks for files in the current directory
(and subdirectories) as tool output. Based on the findings it will recommend other tools or enumeration steps.

This is not an automated scanner. You are expected to review and adjust the recommended commands to fit your situation.

```shell
$ docker run -it --rm -v /path/to/output:/data --user ${UID} ghcr.io/double16/shadycompass:main

shadycompass - https://github.com/double16/shadycompass
Press enter/return at the prompt to refresh data.

[*] Reading hosts from tests/fixtures/etchosts/hosts
[*] Reading nmap facts from tests/fixtures/nmap/open-ports.xml
[*] Reading hosts from /etc/hosts

[$]  1. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. gobuster dir -k -o gobuster-8080-hospital.htb.txt -u http://hospital.htb:8080
[$]  3. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-8080-hospital.htb.json,json http://hospital.htb:8080/FUZZ
[$]  4. dirb http://hospital.htb:8080 -o dirb-8080-hospital.htb.txt
[$]  5. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  6. gobuster dir -k -o gobuster-443-hospital.htb.txt -u https://hospital.htb:443
[$]  7. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-443-hospital.htb.json,json https://hospital.htb:443/FUZZ
[$]  8. dirb https://hospital.htb:443 -o dirb-443-hospital.htb.txt

tests/fixtures shadycompass > use feroxbuster
[*] using feroxbuster for http_buster
[!] configuration is only saved when you run the "save" command

[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

tests/fixtures shadycompass > info 2

# feroxbuster

## tool links
https://github.com/epi052/feroxbuster

## methodology
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#brute-force-directories-and-files

## example command
feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

tests/fixtures shadycompass > exit

$
```

## Run it!

### Source

Running it from source gets the latest but requires python3 and installing some packages:
```shell
$ git clone https://github.com/double16/shadycompass.git
$ cd shadycompass
$ virtualenv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ python3 shadycompass.py /path/to/output
```

### Docker

```shell
$ mkdir -p ${HOME}/.config/shadycompass
$ docker run -it --rm -v ${HOME}/.config/shadycompass:/config -v /path/to/output:/data --user ${UID} ghcr.io/double16/shadycompass:main
```

## Commands

Shady Compass outputs recommendations and then provides a prompt. It will detect changes and update recommendations
after each command, or pressing enter without a command.

```
tests/fixtures shadycompass > help

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
    displays the urls that have been foundfacts
    show current facts (useful for debugging)
```

### info 

Arguments: `n [ ... ]`

Displays detailed information about a recommended tool. Arguments are one or more numbers shown to the left of the
recommendation. The numbers change as recommendations change!

```
[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

tests/fixtures shadycompass > info 2

# feroxbuster

## tool links
https://github.com/epi052/feroxbuster

## methodology
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#brute-force-directories-and-files

## example command
feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure
```

### save

Arguments: none

Save configuration changes made by choosing tools, using commands such as `set`, `unset`, and `use`. Each configuration may be
set at either the global or local level. Local is saved in the current directory and intended for things specific to the
targets. Global changes are in `~/.config/shadycompass/shadycompass.ini` where `~` is your home directory. If you are
using Docker, global changes are saved to `/config/shadycompass.ini`. Local configurations are preferred over global.

### use

Arguments: `[global] <tool> [--reset-options]`

Sets a tool as preferred for each category (vuln scanner, port scanner, etc.) in which it is registered. If the
preferred tool cannot perform a recommended function, another tool may be recommended.

Specify the `global` keyword to configure at the global level. All targets will prefer this tool unless another tool
is configured at the local level.

The `--reset-options` will remove any custom options set for the tool, considering the `global` keyword if specified.

```
[$]  1. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. gobuster dir -k -o gobuster-8080-hospital.htb.txt -u http://hospital.htb:8080
[$]  3. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-8080-hospital.htb.json,json http://hospital.htb:8080/FUZZ
[$]  4. dirb http://hospital.htb:8080 -o dirb-8080-hospital.htb.txt
[$]  5. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  6. gobuster dir -k -o gobuster-443-hospital.htb.txt -u https://hospital.htb:443
[$]  7. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-443-hospital.htb.json,json https://hospital.htb:443/FUZZ
[$]  8. dirb https://hospital.htb:443 -o dirb-443-hospital.htb.txt

tests/fixtures shadycompass > use feroxbuster
[*] using feroxbuster for http_buster
[!] configuration is only saved when you run the "save" command

[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

tests/fixtures shadycompass > use global feroxbuster
[*] using feroxbuster for http_buster
[!] configuration is only saved when you run the "save" command

[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure
```

### option

Arguments: `[global] <tool> args ...`

Add or replace options/arguments for a tool. Options are added to the list unless an existing option is present and
then it is replaced. Any values after one starting with `-` will be considered values for the option and will
replace similar values. The `global` keyword will set for all targets. Any local options will cause global options to
be ignored. Run `use [global] <tool> --reset-options` to reset the options.

```
[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 4 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 4 --insecure

tests/fixtures shadycompass > option feroxbuster --scan-limit 5
[!] configuration is only saved when you run the "save" command

[$]  1. feroxbuster -u https://hospital.htb:443 -o feroxbuster-443-hospital.htb.txt --scan-limit 5 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 -o feroxbuster-8080-hospital.htb.txt --scan-limit 5 --insecure
```

### set

Arguments: `[global] [section.]option value`
            or no arguments

Set a configuration value. The `global` keyword will set for all targets. A local configuration will override a global
one with the same `[section.]option`. The section is optional is defaults to `general`.
See the Configuration section below for available configurations.

```
shadycompass > set global ratelimit 5
[!] configuration is only saved when you run the "save" command

shadycompass > set ratelimit 10
[!] configuration is only saved when you run the "save" command
```

Running `set` with no arguments will show the current configuration, local and global.

```
tests/fixtures shadycompass > set

[tools]
port_scanner = nmap
http_buster = *  # global
vuln_scanner = *  # global

[general]
ratelimit = 5
```

### unset

Arguments: `[global] [section.]option`

Unset a configuration value. The `global` keyword will set for all targets. The section is optional is defaults to
`general`. See the Configuration section below.

```
shadycompass > unset global ratelimit
[!] configuration is only saved when you run the "save" command

shadycompass > unset ratelimit
[!] configuration is only saved when you run the "save" command
```

### reset

Removes all configurations, global and local to the current target directory. You must call `save` to persist.

### tools

Displays the available tools.

### targets

Displays the targets that have been found.

### services

Displays the services that have been found.

### products

Displays the products that have been found.

### urls

Displays the URLs that have been found.

### facts

Displays the things shady compass knows about to make recommendations. This is used for debugging purposes.

## Configuration

### ratelimit

The rate limit is expressed in requests per second. Tools that use other units will convert to be equivalent to
requests per second.

Local setting of ratelimit will apply it to all targets. Global setting will only apply when that target is
considered a production target. See `production` below.

```
shadycompass> set ratelimit 5

shadycompass> unset ratelimit 5

shadycompass> set global ratelimit 8

shadycompass> unset global ratelimit 8
```

### production

Mark the targets as production. Production targets are considered more sensitive. Tools will select safer options. The
user is still expected to know your tools and your targets! Don't copy and paste without reviewing the commands.

Production targets will always use rate limiting, if configured.

```
shadycompass> set production true

shadycompass> set production false

shadycompass> set global production true

shadycompass> unset production
 ```

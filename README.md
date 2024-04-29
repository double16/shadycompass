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

[$]  1. feroxbuster -u http://hospital.htb:8080 --random-agent --extract-links -o feroxbuster-8080-hospital.htb.txt --thorough --scan-limit 6 --insecure
[$]  2. gobuster dir --random-agent --discover-backup -k -o gobuster-8080-hospital.htb.txt -u http://hospital.htb:8080
[$]  3. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-8080-hospital.htb.json,json http://hospital.htb:8080/FUZZ
[$]  4. dirb http://hospital.htb:8080 -o dirb-8080-hospital.htb.txt
[$]  5. feroxbuster -u https://hospital.htb:443 --random-agent --extract-links -o feroxbuster-443-hospital.htb.txt --thorough --scan-limit 6 --insecure
[$]  6. gobuster dir --random-agent --discover-backup -k -o gobuster-443-hospital.htb.txt -u https://hospital.htb:443
[$]  7. wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt --hc 404 -f wfuzz-443-hospital.htb.json,json https://hospital.htb:443/FUZZ
[$]  8. dirb https://hospital.htb:443 -o dirb-443-hospital.htb.txt

tests/fixtures shadycompass > use feroxbuster
[*] using feroxbuster for http_buster
[!] configuration is only saved when you run the "save" command

[$]  1. feroxbuster -u https://hospital.htb:443 --random-agent --extract-links -o feroxbuster-443-hospital.htb.txt --thorough --scan-limit 6 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 --random-agent --extract-links -o feroxbuster-8080-hospital.htb.txt --thorough --scan-limit 6 --insecure

tests/fixtures shadycompass > info 2

# feroxbuster

## tool links
https://github.com/epi052/feroxbuster

## methodology
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#brute-force-directories-and-files

## example command
feroxbuster -u http://hospital.htb:8080 --random-agent --extract-links -o feroxbuster-8080-hospital.htb.txt --thorough --scan-limit 6 --insecure

[$]  1. feroxbuster -u https://hospital.htb:443 --random-agent --extract-links -o feroxbuster-443-hospital.htb.txt --thorough --scan-limit 6 --insecure
[$]  2. feroxbuster -u http://hospital.htb:8080 --random-agent --extract-links -o feroxbuster-8080-hospital.htb.txt --thorough --scan-limit 6 --insecure

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
facts
    show current facts (useful for debugging)
```

TODO: Explain the commands.

## Tools

TODO: Write about how tool selection is done.

# shadycompass

Shady Compass is a tool to help ethical hackers cover enumeration steps. It looks for files in the current directory
(and subdirectories) as tool output. Based on the findings it will recommend other tools or enumeration steps.

What it is not:
1. Automated scanner
2. Vulnerability scanner
3. Fool-proof

TODO: example animated gif

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
$ docker run -it --rm -v /path/to/output:/data --user ${UID} shadycompass:latest
```

## Commands

Shady Compass outputs recommendations and then provides a prompt. It will detect changes and update recommendations
after each command, or pressing enter without a command.

```shell
$ docker run -it --rm -v /path/to/output:/data --user ${UID} shadycompass:latest

shadycompass - https://github.com/double16/shadycompass

Press enter/return at the prompt to refresh data.

[*] Reading hosts from /data/etchosts/hosts
[*] Reading nmap facts from /data/nmap/open-ports.xml
[*] Reading hosts from /etc/hosts

[$] dirb http://localhost:8080
[$] gobuster http://localhost:8080
[$] feroxbuster http://localhost:8080
[$] wfuzz http://localhost:8080

/data shadycompass > help

/data shadycompass > help

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

/data shadycompass > exit

$
```

TODO: Explain the commands.

## Tools

TODO: Write about how tool selection is done.

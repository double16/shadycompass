from shadycompass.config import ConfigRules
from shadycompass.rules.dirb import DirbRules
from shadycompass.rules.feroxbuster import FeroxBusterRules
from shadycompass.rules.gobuster import GoBusterRules
from shadycompass.rules.httpbusting import HttpBusting
from shadycompass.rules.nikto import NiktoRules
from shadycompass.rules.nmap import NmapRules
from shadycompass.rules.nuclei import NucleiRules
from shadycompass.rules.wfuzz import WfuzzRules


class AllRules(
    NmapRules,
    DirbRules,
    FeroxBusterRules,
    GoBusterRules,
    WfuzzRules,
    HttpBusting,
    ConfigRules,
    NucleiRules,
    NiktoRules,
):
    """
    Convenience class to collect all rules.
    """
    pass

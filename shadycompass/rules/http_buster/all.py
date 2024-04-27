from shadycompass.rules.http_buster.dirb import DirbRules
from shadycompass.rules.http_buster.feroxbuster import FeroxBusterRules
from shadycompass.rules.http_buster.gobuster import GoBusterRules
from shadycompass.rules.http_buster.wfuzz import WfuzzRules


class AllRules(
    DirbRules,
    FeroxBusterRules,
    GoBusterRules,
    WfuzzRules,
):
    """
    Convenience class to collect all http buster rules.
    """
    pass

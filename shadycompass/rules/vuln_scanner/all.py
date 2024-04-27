from shadycompass.rules.vuln_scanner.nikto import NiktoRules
from shadycompass.rules.vuln_scanner.nuclei import NucleiRules


class AllRules(
    NucleiRules,
    NiktoRules,
):
    """
    Convenience class to collect all rules.
    """
    pass

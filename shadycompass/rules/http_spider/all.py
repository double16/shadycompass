from shadycompass.rules.http_spider.gospider import GospiderRules
from shadycompass.rules.http_spider.katana import KatanaRules


class AllRules(
    KatanaRules,
    GospiderRules
):
    """
    Convenience class to collect all the rules.
    """
    pass

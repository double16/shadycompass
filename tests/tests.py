from experta import Fact, KnowledgeEngine


def assertFactIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if repr(fact) == repr(f1):
            return
    raise AssertionError(f"{repr(fact)} not found in {engine.facts.values()}")


def assertFactNotIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if repr(fact) == repr(f1):
            raise AssertionError(f"{repr(fact)} found in {engine.facts.values()}")

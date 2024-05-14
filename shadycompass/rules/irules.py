from abc import ABC, abstractmethod
from typing import Union, Iterable

from experta import Fact


class IRules(ABC):
    @abstractmethod
    def declare(self, fact: Fact):
        pass

    @abstractmethod
    def retract(self, fact: Fact):
        pass

    @abstractmethod
    def resolve_command_line(self, tool_name: str, options: list[str], *args) -> list[str]:
        pass

    @abstractmethod
    def recommend_tool(self,
                       category: str,
                       name: str,
                       variant: Union[str, None],
                       command_line: list[str],
                       addr: Union[str, None] = None,
                       hostname: Union[str, None] = None,
                       port: Union[int, None] = None):
        pass

    @abstractmethod
    def get_facts(self) -> Iterable[Fact]:
        pass

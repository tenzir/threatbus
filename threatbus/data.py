from dataclasses import dataclass
from datetime import datetime
from enum import Enum, unique


@unique
class Operation(Enum):
    ADD = "ADD"
    REMOVE = "REMOVE"


@dataclass()
class Intel:
    ts: datetime
    id: str
    data: dict()  # TODO
    operation: Operation


@dataclass()
class Sighting:
    ts: datetime
    intel: str
    context: dict

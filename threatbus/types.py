from dataclasses import dataclass
from datetime import datetime


@dataclass
class Subscription:
    topic: str
    queue: object


@dataclass()
class Intel:
    ts: datetime
    id: int
    data: dict()  # TODO


@dataclass()
class Sighting:
    ts: datetime
    intel_id: int
    context: dict

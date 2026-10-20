from dataclasses import dataclass, field


@dataclass(slots=True)
class Backoff:
    initial: float = 1.0
    maximum: float = 30.0
    _delay: float = field(init=False)

    def __post_init__(self) -> None:
        self._delay = self.initial

    def reset(self) -> None:
        self._delay = self.initial

    def next(self) -> float:
        delay = min(self._delay, self.maximum)
        self._delay = delay * 2
        return delay

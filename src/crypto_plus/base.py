from abc import ABC


class Base(ABC):  # noqa: B024
    def __init__(self):
        self.key = None
        self.keypair = None

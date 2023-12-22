from abc import ABC
from abc import abstractmethod


class Base(ABC):  # noqa: B024
    def __init__(self):
        self.private_key = None
        self.public_key = None

    @property
    def has_private(self) -> bool:
        return self.private_key is not None

    def export_private_key(self, key_format="PEM"):
        if self.has_private:
            return self.private_key.export_key(format=key_format)

    def export_public_key(self, key_format="PEM"):
        return self.public_key.export_key(format=key_format)


class BaseCrypto(Base):
    @abstractmethod
    def encrypt(self, message):
        pass

    @abstractmethod
    def decrypt(self, message):
        pass


class BaseSignature(Base):
    @abstractmethod
    def sign(self, message, **kwargs):
        pass

    @abstractmethod
    def verify(self, message, signature, **kwargs):
        pass

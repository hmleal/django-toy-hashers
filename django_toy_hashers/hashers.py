import codecs
import hashlib

from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare


class ROT13PasswordHasher(BasePasswordHasher):
    algorithm = "rot13"

    def encode(self, password, salt):
        self._check_encode_args(password, salt)
        hash = codecs.encode(salt + password, 'rot_13')
        return f"{self.algorithm}${salt}${hash}"
    
    def verify(self, password, encoded):
        decoded = self.decode(encoded)
        encoded_2 = self.encode(password, decoded["salt"])
        return constant_time_compare(encoded, encoded_2)

    def decode(self, encoded):
        algorithm, salt, hash = encoded.split("$", 2)
        assert algorithm == self.algorithm
        return {"algorithm": algorithm, "salt": salt, "hash": hash}

    def safe_summary(self, encoded):
        decoded = self.decode(encoded)
        return {
            "algorithm": decoded["algorithm"],
            "salt": decoded["salt"],
            "hash": decoded["hash"]
        }

    def harden_runtime(self, password, encoded):
        pass


class MD5PasswordHasher(BasePasswordHasher):
    algorithm = "md5_custom"
    iterations = 10

    def encode(self, password, salt, iterations=None):
        self._check_encode_args(password, salt)
        iterations = iterations or self.iterations

        password_hash = (salt + password).encode('UTF-8')
        for _ in range(iterations):
            password_hash = hashlib.md5(password_hash).digest()

        password_has_hex = password_hash.hex()
        return "%s$%d$%s$%s" % (self.algorithm, 10, salt, password_has_hex)

    def verify(self, password, encoded):
        decoded = self.decode(encoded)
        encoded_2 = self.encode(password, decoded["salt"])
        return constant_time_compare(encoded, encoded_2)

    def decode(self, encoded):
        algorithm, iterations, salt, hash_val = encoded.split("$", 3)
        assert algorithm == self.algorithm
        return {
            "algorithm": algorithm,
            "iterations": int(iterations),
            "salt": salt,
            "hash": hash_val
        }

    def safe_summary(self, encoded):
        decoded = self.decode(encoded)
        return {
            "algorithm": decoded["algorithm"],
            "iterations": 10,
            "salt": decoded["salt"],
            "hash": decoded["hash"],
        }

    def harden_runtime(self, password, encoded):
        pass


class PlainTextPasswordHasher(BasePasswordHasher):
    algorithm = "plain_text"

    def encode(self, password, salt):
        self._check_encode_args(password, salt)
        return f"{self.algorithm}${salt}${password}"

    def verify(self, password, encoded):
        decoded = self.decoded(encoded)
        encoded_2 = self.encode(password, decoded["salt"])
        return constant_time_compare(encoded, encoded_2)

    def decode(self, encoded):
        algorithm, salt, password_hash = encoded.split("$", 2)
        assert algorithm == self.algorithm
        return {"algorithm": algorithm, "salt": salt, "hash": password_hash}

    def safe_summary(self, encoded):
        decoded = self.decode(encoded)
        return {
            "algorithm": decoded["algorithm"],
            "password": decoded["hash"]
        }

    def harden_runtime(self, password, encoded):
        pass

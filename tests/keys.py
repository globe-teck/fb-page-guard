"""Throwaway Ed25519 identities for tests, made fresh in a temp dir."""
import tempfile
from pathlib import Path

from fbguard import approval as appr


class Identities:
    def __init__(self, *names):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.lines = {}
        for n in names:
            self.lines[n] = appr.generate(n, self.dir / f"{n}.key")
        self.trusted_file = self.dir / "trusted_keys"
        self.trusted_file.write_text("# test keys\n" + "\n".join(self.lines.values()) + "\n")

    def key_path(self, name):
        return self.dir / f"{name}.key"

    def signer(self, name):
        return appr.Signer(name, self.key_path(name))

    def trusted(self):
        return appr.TrustedKeys.load(self.trusted_file)

    def cleanup(self):
        self._tmp.cleanup()

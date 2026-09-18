"""Synthetic durable-I/O ratchet cases; never compile or execute product code."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "store_durability_gate",
    Path(__file__).resolve().parents[1] / "check_store_durability_adoption.py",
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

RENAME = "    std::fs::rename(&staged, &published).unwrap();\n"


class StoreDurability(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="store-durability-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, content):
        file = self.root / "tool-runtime-core/src" / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf8")

    def test_production_rename_is_counted(self):
        self.write("store.rs", "pub fn publish() {\n" + RENAME + "}\n")
        self.assertEqual(
            GATE.scan(self.root),
            {"tool-runtime-core/src/store.rs": {"hand_rolled_atomic_write": 1}},
        )

    def test_cfg_test_module_file_is_not_a_store_surface(self):
        self.write("spawn.rs", "pub fn spawn() {}\n\n#[cfg(test)]\nmod tests;\n")
        self.write("spawn/tests.rs", "#[test]\nfn swap() {\n" + RENAME + "}\n")
        self.assertEqual(GATE.scan(self.root), {})

    def test_cfg_test_module_directory_beside_mod_rs_is_not_a_store_surface(self):
        self.write("spawn/mod.rs", "#[cfg(test)]\n#[allow(dead_code)]\npub(crate) mod cases;\n")
        self.write("spawn/cases/mod.rs", "fn swap() {\n" + RENAME + "}\n")
        self.assertEqual(GATE.scan(self.root), {})

    def test_module_without_cfg_test_stays_counted(self):
        self.write("spawn.rs", "mod publish;\n")
        self.write("spawn/publish.rs", "pub fn publish() {\n" + RENAME + "}\n")
        self.assertEqual(
            GATE.scan(self.root),
            {"tool-runtime-core/src/spawn/publish.rs": {"hand_rolled_atomic_write": 1}},
        )

    def test_inline_test_block_stays_inside_its_file_count(self):
        self.write(
            "store.rs",
            "pub fn publish() {\n" + RENAME + "}\n\n#[cfg(test)]\nmod tests {\n" + RENAME + "}\n",
        )
        self.assertEqual(
            GATE.scan(self.root),
            {"tool-runtime-core/src/store.rs": {"hand_rolled_atomic_write": 2}},
        )


if __name__ == "__main__":
    unittest.main()

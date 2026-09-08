from __future__ import print_function

import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "src", "data", "build_runtime_source_readback.py")


class RuntimeSourceReadbackTest(unittest.TestCase):
    def make_source(self, directory, name, data):
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_tool(self, arguments):
        return subprocess.call([sys.executable, SCRIPT] + arguments,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_deterministic_and_no_path_leak(self):
        directory = tempfile.mkdtemp()
        source_a = self.make_source(directory, "one.bin", b"one")
        source_b = self.make_source(directory, "two.bin", b"two")
        first = os.path.join(directory, "first.json")
        second = os.path.join(directory, "second.json")
        arguments = ["--artifact", "phase2.b18.source=%s" % source_a,
                     "--artifact", "phase3.s13207.inventory=%s" % source_b]
        self.assertEqual(0, self.run_tool(arguments + ["--output", first]))
        reversed_arguments = ["--artifact", "phase3.s13207.inventory=%s" % source_b,
                              "--artifact", "phase2.b18.source=%s" % source_a]
        self.assertEqual(0, self.run_tool(reversed_arguments + ["--output", second]))
        with open(first, "rb") as left, open(second, "rb") as right:
            self.assertEqual(left.read(), right.read())
        with open(first, "r") as handle:
            receipt = json.load(handle)
        self.assertEqual(2, len(receipt["artifacts"]))
        self.assertNotIn(directory, json.dumps(receipt, sort_keys=True))

    def test_duplicate_and_unsafe_id_fail(self):
        directory = tempfile.mkdtemp()
        source = self.make_source(directory, "source.bin", b"x")
        output = os.path.join(directory, "out.json")
        self.assertNotEqual(0, self.run_tool(["--artifact", "same=%s" % source,
                                              "--artifact", "same=%s" % source,
                                              "--output", output]))
        self.assertNotEqual(0, self.run_tool(["--artifact", "../unsafe=%s" % source,
                                              "--output", output]))


if __name__ == "__main__":
    unittest.main()

"""Local, synthetic tests only; no graph loading or execution authority."""
import copy
import hashlib
import json
import unittest

from scripts.e139_source_derivation import DerivationError, derive, SCHEMA


def sha(value):
    return hashlib.sha256(value).hexdigest()


def specification(data=b"old old", effective=b"new new"):
    return {"schema": SCHEMA,
            "origins": [{"name": "module", "sha256": sha(data),
                         "effective_sha256": sha(effective)}],
            "rules": [{"source": "module", "old_hex": b"old".hex(),
                       "new_hex": b"new".hex(), "count": 2}]}


class DerivationTests(unittest.TestCase):
    def test_exact_and_defensive_snapshots(self):
        spec = specification()
        sources = {"module": b"old old"}
        result = derive(sources, spec)
        manifest = result.public_manifest()
        self.assertEqual(result.private_sources(), {"module": b"new new"})
        self.assertEqual(manifest["sources"][0]["effective_sha256"], sha(b"new new"))
        canonical = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=True,
                                            separators=(",", ":")).encode("ascii")
        self.assertEqual(manifest["spec_sha256"], sha(canonical(spec)))
        self.assertEqual(manifest["rules_sha256"], sha(canonical(spec["rules"])))
        original_manifest = copy.deepcopy(manifest)
        spec["rules"][0]["new_hex"] = "00"
        sources["module"] = b"tamper"
        result.private_sources()["module"] = b"tamper"
        manifest["sources"][0]["effective_sha256"] = "tamper"
        self.assertEqual(result.public_manifest(), original_manifest)
        self.assertEqual(result.private_sources()["module"], b"new new")

    def test_pins_and_counts(self):
        for field in ("sha256", "effective_sha256"):
            spec = specification()
            spec["origins"][0][field] = "0" * 64
            with self.assertRaises(DerivationError):
                derive({"module": b"old old"}, spec)
        for count in (0, -1, True, 1, 3, 65537, "2"):
            spec = specification()
            spec["rules"][0]["count"] = count
            with self.subTest(count=count), self.assertRaises(DerivationError):
                derive({"module": b"old old"}, spec)

    def test_duplicate_missing_and_unknown(self):
        variants = []
        spec = specification()
        spec["rules"].append(dict(spec["rules"][0]))
        variants.append(spec)
        spec = specification()
        spec["origins"].append(dict(spec["origins"][0]))
        variants.append(spec)
        spec = specification()
        spec["rules"][0]["source"] = "unknown"
        variants.append(spec)
        spec = specification()
        del spec["origins"][0]["effective_sha256"]
        variants.append(spec)
        spec = specification()
        spec["extra"] = True
        variants.append(spec)
        for spec in variants:
            with self.assertRaises(DerivationError):
                derive({"module": b"old old"}, spec)
        with self.assertRaises(DerivationError):
            derive({"module": b"old old", "unlisted": b""}, specification())

    def test_malformed_and_noop(self):
        for old, new in (("", "00"), ("0", "00"), ("AA", "00"),
                         (" 00", "00"), ("gg", "00"), (None, "00"),
                         (b"old".hex(), b"old".hex()), ("00" * 4097, "00")):
            spec = specification()
            spec["rules"][0].update(old_hex=old, new_hex=new)
            with self.subTest(old=old), self.assertRaises(DerivationError):
                derive({"module": b"old old"}, spec)

    def test_identity_unicode_and_deletion(self):
        data = '中文“原话” E138'.encode("utf-8")
        spec = specification(data, data)
        spec["rules"] = []
        self.assertEqual(derive({"module": data}, spec).private_sources()["module"], data)
        effective = data.replace('中文'.encode(), b"")
        spec = specification(data, effective)
        spec["rules"] = [{"source": "module", "old_hex": '中文'.encode().hex(),
                          "new_hex": "", "count": 1}]
        self.assertEqual(derive({"module": data}, spec).private_sources()["module"], effective)

    def test_simultaneous_not_cascading(self):
        spec = specification(b"a b", b"b c")
        spec["rules"] = [{"source": "module", "old_hex": old.hex(),
                          "new_hex": new.hex(), "count": 1}
                         for old, new in ((b"a", b"b"), (b"b", b"c"))]
        result = derive({"module": b"a b"}, spec)
        spec["rules"].reverse()
        self.assertEqual(result.public_manifest(), derive({"module": b"a b"}, spec).public_manifest())
        self.assertEqual(result.private_sources()["module"], b"b c")

    def test_overlaps_rejected(self):
        spec = specification(b"aaa", b"unused")
        spec["rules"] = [{"source": "module", "old_hex": b"aa".hex(),
                          "new_hex": b"b".hex(), "count": 2}]
        with self.assertRaisesRegex(DerivationError, "overlapping"):
            derive({"module": b"aaa"}, spec)
        spec["rules"] = [{"source": "module", "old_hex": old.hex(),
                          "new_hex": b"z".hex(), "count": 1}
                         for old in (b"ab", b"bc")]
        spec["origins"][0]["sha256"] = sha(b"abc")
        with self.assertRaisesRegex(DerivationError, "overlapping"):
            derive({"module": b"abc"}, spec)

    def test_source_and_rule_bounds(self):
        data = b"x" * (4 * 1024 * 1024 + 1)
        spec = specification(data, data)
        spec["rules"] = []
        with self.assertRaisesRegex(DerivationError, "source size"):
            derive({"module": data}, spec)
        spec = specification()
        spec["rules"] *= 257
        with self.assertRaisesRegex(DerivationError, "rule count"):
            derive({"module": b"old old"}, spec)

    def test_effective_expansion_and_occurrence_bounds(self):
        data = b"x" * 1025
        spec = specification(data, b"")
        spec["rules"] = [{"source": "module", "old_hex": "78",
                          "new_hex": "79" * 4096, "count": 1025}]
        with self.assertRaisesRegex(DerivationError, "effective source size"):
            derive({"module": data}, spec)
        data = b"x" * 65537
        spec = specification(data, b"")
        spec["rules"] = [{"source": "module", "old_hex": "78",
                          "new_hex": "79", "count": 65536}]
        with self.assertRaisesRegex(DerivationError, "excess occurrences"):
            derive({"module": data}, spec)


if __name__ == "__main__":
    unittest.main()

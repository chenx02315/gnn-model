from __future__ import print_function

import csv
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))
import build_candidate_space
import build_formal_candidate_space_v2 as formal


class Args(object):
    pass


class FormalCandidateSpaceTests(unittest.TestCase):
    def write_tsv(self, path, fields, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)

    def test_builds_roster_and_reproduces_phase4(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            p3, p4, p2 = root/"p3", root/"p4", root/"p2"
            fields = ("candidate", "h_patterns", "m_patterns", "f_patterns",
                      "h_cycles", "m_cycles", "f_cycles", "total_cycles",
                      "detected_faults", "f_minus_one_patterns",
                      "f_minus_one_detected", "h_result", "m_result", "f_result",
                      "result_status")
            phase4_normalized = []
            for circuit in formal.ROSTER:
                for alias, scheme, mode_stack, flat_name, phase2_name in formal.LAYOUT:
                    row = {field:"" for field in fields}
                    row.update(candidate="1", h_patterns="4", m_patterns="2" if scheme == "HMF" else "0",
                               f_patterns="3", h_cycles="10", m_cycles="5" if scheme == "HMF" else "0",
                               f_cycles="7", total_cycles="22" if scheme == "HMF" else "17",
                               detected_faults="95", f_minus_one_patterns="2",
                               f_minus_one_detected="94", h_result="H", m_result="M" if scheme == "HMF" else "",
                               f_result="F", result_status="PASS")
                    if circuit in formal.PHASE3:
                        self.write_tsv(p3/circuit/flat_name, fields, [row])
                    elif circuit in formal.PHASE4:
                        self.write_tsv(p4/circuit/flat_name, fields, [row])
                        phase4_normalized.append(formal.normalized_row(
                            circuit, alias, scheme, mode_stack, "1", row,
                            circuit+"/"+flat_name, 2))
                    else:
                        p2_fields = tuple(field for field in fields if field != "candidate")
                        p2_row = dict((field, row[field]) for field in p2_fields)
                        self.write_tsv(p2/circuit/phase2_name, p2_fields, [p2_row])
            normalized_v1 = root/"phase4_v1.tsv"
            self.write_tsv(normalized_v1, formal.NORMALIZED_FIELDS, phase4_normalized)
            actions, total, eligible, skipped = build_candidate_space.build(str(normalized_v1))
            old_actions = root/"candidate_space_v1.tsv"
            build_candidate_space.write(str(normalized_v1), actions, total, eligible, skipped,
                                        str(old_actions), str(root/"old_audit.json"))
            args=Args(); args.phase3_root=str(p3); args.phase4_root=str(p4); args.phase2_root=str(p2)
            args.phase4_normalized_v1=str(normalized_v1); args.phase4_candidate_space_v1=str(old_actions)
            args.output_root=str(root/"output")
            self.assertEqual(0, formal.build(args))
            with (root/"output"/"candidate_space_v2.tsv").open(encoding="utf-8") as stream:
                rows=list(csv.DictReader(stream,delimiter="\t"))
            self.assertEqual(set(formal.ROSTER), {row["circuit"] for row in rows})
            self.assertEqual(16, len(rows))
            with (root/"output"/"receipt_v2.json").open(encoding="utf-8") as stream:
                self.assertIn('"status": "PASS_BUILD_REPEAT_AGGREGATION_PENDING"', stream.read())


if __name__ == "__main__":
    unittest.main()

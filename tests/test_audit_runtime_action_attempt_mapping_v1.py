from __future__ import print_function

import csv
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))
import audit_runtime_action_attempt_mapping_v1 as audit
from runtime_schema import MANIFEST_V2_FIELDS


class MappingTests(unittest.TestCase):
    def write_tsv(self, path, fields, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t", lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)

    def test_parse_f_key_variants(self):
        self.assertEqual(("15", ""), audit.parse_f_key("F_x_cov95_HF_c1_h15_f10_v1", "HF"))
        self.assertEqual(("15", "6"), audit.parse_f_key("F_x_cov95_HMF_c1_h15_m6_f10_v1", "HMF"))
        self.assertEqual(("101", ""), audit.parse_f_key("F_x_cov95v2_HF_refine_h101_F_p2", "HF"))
        self.assertEqual(("24", "11"), audit.parse_f_key("F_x_cov95v2_HMF_refine_h24_m11_F_p2", "HMF"))

    def test_direct_and_search_attempts_map_without_selecting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            circuits = sorted(audit.FORMAL_CIRCUITS)
            actions = [{"action_uid":c+":HF:h4","circuit":c,"action_scheme":"HF",
                        "mode_stack":"H64-F4","h_patterns":"4","m_patterns":"",
                        "repeat_measurement_count":"1","source_candidate_uids":c+":hf_coarse:H64-F4:1",
                        "source_stages":"hf_coarse","outcome_conflict":"false","outcome_conflict_fields":""}
                       for c in circuits]
            self.write_tsv(root/"actions.tsv", audit.ACTION_FIELDS, actions)
            base = dict((field, "") for field in MANIFEST_V2_FIELDS)
            cross_stage_circuit = circuits[0]
            for circuit in circuits:
                measurement = {"candidate":"1","h_patterns":"4","m_patterns":"0","result_status":"PASS",
                               "h_result":"/r/H_"+circuit+"_cov95v2_HF_c01_H_p4","m_result":"",
                               "f_result":"/r/F_"+circuit+"_cov95v2_HF_c01_h4_F_p3"}
                noneligible = {"candidate":"2","h_patterns":"5","m_patterns":"0",
                               "result_status":"TARGET_BEFORE_F",
                               "h_result":"/r/H_"+circuit+"_cov95v2_HF_c02_H_p5","m_result":"",
                               "f_result":"/r/F_"+circuit+"_cov95v2_HF_c02_h5_F_p1"}
                self.write_tsv(root/"measurements"/circuit/"02_hf_coarse__measurements.tsv",
                               tuple(measurement), [measurement, noneligible])
                for alias, layout in audit.SOURCE_LAYOUT.items():
                    if alias == "hf_coarse":
                        continue
                    stage, filename, scheme = layout
                    filler = dict(noneligible)
                    filler.update(candidate="1", h_patterns="9",
                                  m_patterns="2" if scheme == "HMF" else "0",
                                  h_result="/r/H_filler", m_result="/r/M_filler" if scheme == "HMF" else "",
                                  f_result="/r/F_filler")
                    self.write_tsv(root/"measurements"/circuit/filename,
                                   tuple(filler), [filler])
                rows=[]
                for suffix, mode, run_id in (("H","H",circuit+"_cov95v2_HF_c01_H_p4"),
                                               ("F1","F","F_"+circuit+"_cov95v2_HF_c01_h4_F_p1"),
                                               ("F3","F","F_"+circuit+"_cov95v2_HF_c01_h4_F_p3"),
                                               ("NH","H",circuit+"_cov95v2_HF_c02_H_p5"),
                                               ("NF","F","F_"+circuit+"_cov95v2_HF_c02_h5_F_p1")):
                    source_name = ("H_" + run_id if mode == "H" else run_id)
                    attempt_id=circuit+suffix
                    attempt_stage = "logs" if circuit == cross_stage_circuit and suffix == "H" else "02_hf_coarse"
                    row=dict(base); row.update(attempt_id=attempt_id,circuit=circuit,stage=attempt_stage,mode=mode,
                                               run_id=run_id,retry_group_id=run_id,retry_order="1",
                                               source_log_path="/r/"+source_name+".driver.log")
                    rows.append(row)
                self.write_tsv(root/"manifests"/(circuit+"_attempt_manifest_v2_remediated.tsv"), MANIFEST_V2_FIELDS, rows)
            code=audit.audit(str(root/"actions.tsv"),str(root/"measurements"),str(root/"manifests"),str(root/"out"))
            self.assertEqual(0,code)
            with (root/"out"/"invocation_attempt_edges_v1.tsv").open(encoding="utf-8") as stream:
                edges=list(csv.DictReader(stream,delimiter="\t"))
            self.assertEqual(set(c+s for c in circuits for s in ("H","F1","F3")),
                             {row["attempt_id"] for row in edges})
            cross_edge = next(row for row in edges if row["attempt_id"] == cross_stage_circuit+"H")
            self.assertEqual("DIRECT_RESULT_BASENAME_CROSS_STAGE", cross_edge["mapping_rule"])
            with (root/"out"/"excluded_attempts_v1.tsv").open(encoding="utf-8") as stream:
                excluded=list(csv.DictReader(stream,delimiter="\t"))
            self.assertEqual(set(c+s for c in circuits for s in ("NH","NF")),
                             {row["attempt_id"] for row in excluded})
            self.assertEqual({"NON_ELIGIBLE_SOURCE_INVOCATION"},
                             {row["exclusion_reason"] for row in excluded})


if __name__ == "__main__":
    unittest.main()

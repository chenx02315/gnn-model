import unittest

from src.models import ranking_v5_execution_boundary as boundary
from src.models.runtime_ranking_v3 import FEATURES, digest


def rows():
    values = []
    for circuit, family in (("aes_core", "iwls_aes_core"), ("s13207", "iscas89_s13207"),
                            ("s15850", "iscas89_s15850"), ("s35932", "iscas89_s35932"),
                            ("s38417", "iscas89_s38417"), ("spi", "iwls_spi")):
        for index in range(2):
            row = {"action_uid": circuit + str(index), "circuit": circuit, "family": family, "role": "TRAIN"}
            row.update({name: float(index + 1) for name in FEATURES}); values.append(row)
    return values


def request():
    all_rows = rows(); held = "iwls_aes_core"
    return {"scope": boundary.SCOPE, "source_sha256": boundary.SOURCE_SHA256, "family": held,
            "seed": boundary.SEEDS[0], "model": boundary.MODEL, "rows": all_rows,
            "fit_cycles": {r["action_uid"]: 10 + (r["action_uid"].endswith("1")) for r in all_rows if r["family"] != held}}


def binding():
    return {path: "e" * 64 for path in boundary.REQUIRED_SOURCE_BINDINGS}


def release(binding):
    return {"schema": "ranking-v5-train-execution-release-v1", "status": "PASS_V5_TRAIN_EXECUTION_AUTHORIZED",
            "source_sha256": boundary.SOURCE_SHA256, "package_receipt_sha256": boundary.PACKAGE_SHA256,
            "roles": ["TRAIN"], "seeds": list(boundary.SEEDS), "model": boundary.MODEL, "epochs": 120,
            "feature_count": 7, "optimizer": {"name": "Adam", "lr": .001, "weight_decay": .0001}, "K": 10,
            "epsilon": "101/100", "worker_limits": {"worker_count": 1, "threads": 1, "as_limit_bytes": 8 * 1024 ** 3, "rss_limit_bytes": 1024 ** 3},
            "retry_count": 0, "user_authorization_id": "operator-1", "user_authorization_sha256": "a" * 64,
            "independent_review": True, "independent_review_receipt_sha256": "b" * 64, "source_binding": binding,
            "synthetic_gate": {"kind": "raw_log", "raw_log_sha256": boundary.V5_KERNEL_RAW_LOG_SHA256}}


class BoundaryTests(unittest.TestCase):
    def callbacks(self, events, tamper=None):
        state = {}
        def fit(prepared, recipe, seed):
            events.append("fit"); self.assertNotIn("held", prepared); return object()
        def predict(model, uids, features): events.append("predict"); return {uid: float(-i) for i, uid in enumerate(uids)}
        def model_sha256(model): events.append("model-sha"); return "c" * 64
        def persist_model(model, expected): events.append("model"); return "d" * 64 if tamper == "model" else expected
        def persist_freeze(payload, sha):
            events.append("freeze"); state["payload"], state["sha"] = payload, sha
            return "d" * 64 if tamper == "freeze" else sha
        def reread(sha):
            events.append("reread")
            return ({}, sha) if tamper == "reread" else (state["payload"], state["sha"])
        def held(uids, sha): events.append("held"); return {uid: {"execution_status": "SUCCESS", "is_d95_feasible": 1, "total_cycles": 10, "policy_charged_runtime_s": 1} for uid in uids}
        return dict(fit=fit, predict=predict, model_sha256=model_sha256, persist_model=persist_model, persist_freeze=persist_freeze,
                    read_frozen=reread, load_held_labels=held)

    def test_order_and_replay(self):
        events=[]; sources=binding()
        receipt=boundary.execute(request(), release(sources), sources, **self.callbacks(events))
        self.assertEqual(events, ["fit", "model-sha", "model", "predict", "freeze", "reread", "held"])
        self.assertTrue(receipt["held_labels_replayed"]); self.assertEqual(receipt["freeze_sha256"], receipt["metrics"]["freeze_sha256"])

    def test_bad_model_ack_or_readback_blocks_held_loader(self):
        sources=binding()
        for tamper in ("model", "freeze", "reread"):
            events=[]
            with self.assertRaises(ValueError): boundary.execute(request(), release(sources), sources, **self.callbacks(events, tamper))
            self.assertNotIn("held", events)

    def test_held_label_join_is_replayed_only_after_readback(self):
        events=[]; sources=binding(); callbacks=self.callbacks(events)
        callbacks["load_held_labels"] = lambda uids, sha: {}
        with self.assertRaises(ValueError):
            boundary.execute(request(), release(sources), sources, **callbacks)
        self.assertEqual(events, ["fit", "model-sha", "model", "predict", "freeze", "reread"])

    def test_callbacks_cannot_mutate_audited_input_snapshots(self):
        events=[]; sources=binding(); req=request(); rel=release(sources)
        expected_request, expected_release, expected_binding = digest(req), digest(rel), digest(sources)
        callbacks=self.callbacks(events)
        original_fit=callbacks["fit"]
        def mutating_fit(prepared, recipe, seed):
            req["rows"][0]["scheme_hf"] = float("nan")
            rel["status"] = "PASS_V4_TRAIN_ONLY_EXECUTION"
            sources["src/models/runtime_ranking_v3.py"] = "0" * 64
            return original_fit(prepared, recipe, seed)
        callbacks["fit"] = mutating_fit
        receipt=boundary.execute(req, rel, binding(), **callbacks)
        self.assertEqual((receipt["canonical_request_sha256"], receipt["release_sha256"], receipt["source_binding_sha256"]),
                         (expected_request, expected_release, expected_binding))

    def test_fit_cannot_mutate_held_normalizer_or_recipe_receipt(self):
        events=[]; sources=binding(); req=request(); expected_recipe = None
        callbacks=self.callbacks(events)
        observed = {}
        original_fit, original_predict = callbacks["fit"], callbacks["predict"]
        def mutating_fit(prepared, recipe, seed):
            nonlocal expected_recipe
            expected_recipe = digest(recipe)
            prepared["normalizer"] = ((999.,) * 7, (1.,) * 7)
            recipe["families"].clear()
            req["seed"] = 0
            return original_fit(prepared, recipe, seed)
        def observing_predict(model, uids, features):
            observed["features"] = features
            return original_predict(model, uids, features)
        callbacks["fit"], callbacks["predict"] = mutating_fit, observing_predict
        receipt=boundary.execute(req, release(sources), sources, **callbacks)
        self.assertEqual(observed["features"][0], (-1.0,) * 7)
        self.assertEqual(receipt["seed"], boundary.SEEDS[0])
        self.assertEqual(receipt["head_recipe_sha256"], expected_recipe)

    def test_release_and_request_refusals_invoke_no_callbacks(self):
        sources=binding()
        cases=[]
        bad=release(sources); bad["status"]="PASS_V4_TRAIN_ONLY_EXECUTION"; cases.append((request(),bad,sources))
        bad=release(sources); bad["independent_review"]=1; cases.append((request(),bad,sources))
        bad=release(sources); bad["independent_review"]=False; cases.append((request(),bad,sources))
        bad=release(sources); bad["epochs"]=120.0; cases.append((request(),bad,sources))
        bad=release(sources); bad["K"]=True; cases.append((request(),bad,sources))
        bad=release(sources); bad["extra"]=1; cases.append((request(),bad,sources))
        bad=release(sources); bad["synthetic_gate"]={"kind":"manifest_bound","manifest_sha256":"f"*64,"raw_log_sha256":boundary.V5_KERNEL_RAW_LOG_SHA256}; cases.append((request(),bad,sources))
        cases.append((dict(request(), source_sha256="0" * 64),release(sources),sources))
        bad=release(sources); bad["package_receipt_sha256"]="0" * 64; cases.append((request(),bad,sources))
        bad_request=dict(request()); bad_request["seed"]=20260824.0; cases.append((bad_request,release(sources),sources))
        unsafe={"../escape": "a" * 64}; cases.append((request(),release(unsafe),unsafe))
        bad_request=dict(request()); bad_request["held_labels"]={}; cases.append((bad_request,release(sources),sources))
        for req, rel, expected in cases:
            events=[]
            with self.assertRaises(ValueError): boundary.execute(req,rel,expected,**self.callbacks(events))
            self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()

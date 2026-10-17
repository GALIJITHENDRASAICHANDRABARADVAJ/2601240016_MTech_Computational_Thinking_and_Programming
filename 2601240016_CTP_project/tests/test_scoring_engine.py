import unittest

from tests.helpers import default_config
from src.config import ConfigError, validate_config
from src.scoring_engine import ScoringEngine


def make_config(rules, decisive=90):
    cfg = default_config()
    cfg["rules"] = rules
    cfg["greedy"]["decisive_score"] = decisive
    return cfg


def rule(rid, weight, feature, category="phishing", op="true", **extra):
    cond = {"feature": feature, "op": op}
    if "value" in extra:
        cond["value"] = extra.pop("value")
    return {"id": rid, "name": rid, "category": category, "weight": weight, "condition": cond, **extra}


class ScoringTests(unittest.TestCase):
    def test_greedy_order_by_absolute_weight(self):
        engine = ScoringEngine(make_config([rule("A", 5, "x"), rule("B", -30, "x"), rule("C", 20, "x"), rule("D", 20, "x")]))
        self.assertEqual([r.rule_id for r in engine.rules], ["B", "C", "D", "A"])

    def test_categories_accumulate_separately(self):
        engine = ScoringEngine(make_config([
            rule("P", 20, "x", "phishing"), rule("S", 15, "x", "spam"), rule("B", 10, "x", "both")]))
        out = engine.score({"x": True})
        self.assertEqual(out.phishing_score, 30)
        self.assertEqual(out.spam_score, 25)
        self.assertEqual({m.rule_id for m in out.matches}, {"P", "S", "B"})

    def test_unmatched_rules_do_not_fire(self):
        out = ScoringEngine(make_config([rule("P", 20, "x")])).score({"x": False})
        self.assertEqual(out.matches, [])
        self.assertEqual(out.phishing_score, 0)

    def test_missing_feature_does_not_fire_or_crash(self):
        out = ScoringEngine(make_config([rule("P", 20, "nope", op="gte", value=1)])).score({})
        self.assertEqual(out.matches, [])

    def test_per_hit_scales_and_caps(self):
        engine = ScoringEngine(make_config([rule("K", 20, "n", "spam", op="gte", value=1, per_hit=6)]))
        self.assertEqual(engine.score({"n": 1}).spam_score, 6)
        self.assertEqual(engine.score({"n": 2}).spam_score, 12)
        self.assertEqual(engine.score({"n": 10}).spam_score, 20)  # capped at weight
        self.assertEqual(engine.score({"n": 0}).spam_score, 0)

    def test_operators(self):
        cfg = make_config([
            rule("GTE", 1, "n", op="gte", value=3),
            rule("EQ", 2, "s", op="eq", value="yes"),
            rule("IN", 4, "s", op="in", value=["yes", "maybe"]),
        ])
        out = ScoringEngine(cfg).score({"n": 3, "s": "yes"})
        self.assertEqual(out.phishing_score, 7)
        out = ScoringEngine(cfg).score({"n": 2, "s": "no"})
        self.assertEqual(out.phishing_score, 0)

    def test_negative_rules_mitigate_and_floor_at_zero(self):
        engine = ScoringEngine(make_config([rule("P", 10, "x"), rule("N", -50, "x", "both")]))
        out = engine.score({"x": True})
        self.assertEqual(out.phishing_score, 0)
        self.assertEqual(out.spam_score, 0)

    def test_scores_clamped_to_100(self):
        engine = ScoringEngine(make_config([rule(f"R{i}", 40, "x") for i in range(5)], decisive=10_000))
        self.assertEqual(engine.score({"x": True}).phishing_score, 100)

    def test_early_exit_skips_remaining_rules(self):
        rules = [rule("BIG1", 60, "x"), rule("BIG2", 40, "x"), rule("SMALL1", 5, "x"), rule("SMALL2", 4, "x")]
        out = ScoringEngine(make_config(rules, decisive=90)).score({"x": True})
        self.assertTrue(out.early_exit)
        self.assertEqual(out.rules_evaluated, 2)
        self.assertEqual({m.rule_id for m in out.matches}, {"BIG1", "BIG2"})

    def test_no_early_exit_below_decisive(self):
        rules = [rule("A", 30, "x"), rule("B", 20, "x")]
        out = ScoringEngine(make_config(rules, decisive=90)).score({"x": True})
        self.assertFalse(out.early_exit)
        self.assertEqual(out.rules_evaluated, 2)

    def test_evidence_in_detail_with_dotted_path(self):
        engine = ScoringEngine(make_config([rule("U", 10, "flag", evidence="url_flags.ip_host")]))
        out = engine.score({"flag": True, "url_flags": {"ip_host": ["192.0.2.1"]}})
        self.assertIn("192.0.2.1", out.matches[0].detail)


class ConfigValidationTests(unittest.TestCase):
    def test_default_config_is_valid(self):
        validate_config(default_config())

    def _expect_error(self, mutate):
        cfg = default_config()
        mutate(cfg)
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_invalid_threshold(self):
        self._expect_error(lambda c: c["thresholds"].update(phishing=0))
        self._expect_error(lambda c: c["thresholds"].update(spam="high"))

    def test_duplicate_rule_id(self):
        self._expect_error(lambda c: c["rules"].append(dict(c["rules"][0])))

    def test_bad_category_and_op(self):
        self._expect_error(lambda c: c["rules"][0].update(category="malware"))
        self._expect_error(lambda c: c["rules"][0]["condition"].update(op="regex"))

    def test_missing_value_for_gte(self):
        self._expect_error(lambda c: c["rules"].append(rule("Z", 1, "x", op="gte")))

    def test_missing_lexicon(self):
        self._expect_error(lambda c: c["lexicons"].pop("threats"))

    def test_not_an_object(self):
        with self.assertRaises(ConfigError):
            validate_config([])


if __name__ == "__main__":
    unittest.main()

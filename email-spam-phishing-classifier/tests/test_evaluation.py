import unittest

from src.evaluation import compute_metrics, evaluate_results
from src.models import ClassificationResult


def res(true, pred):
    return ClassificationResult("id", "s", "", "", pred, 0, 0, 0, true_label=true,
                                error="x" if pred == "error" else None)


class MetricsTests(unittest.TestCase):
    def test_hand_computed_example(self):
        # true:  L L L L S S S P P P
        # pred:  L L L S S S L P P L
        y_true = ["legitimate"] * 4 + ["spam"] * 3 + ["phishing"] * 3
        y_pred = ["legitimate", "legitimate", "legitimate", "spam", "spam", "spam", "legitimate",
                  "phishing", "phishing", "legitimate"]
        m = compute_metrics(y_true, y_pred)
        self.assertEqual(m.confusion_matrix, [[3, 1, 0], [1, 2, 0], [1, 0, 2]])
        self.assertAlmostEqual(m.accuracy, 7 / 10)
        legit, spam, phish = (m.per_class[k] for k in ("legitimate", "spam", "phishing"))
        self.assertAlmostEqual(legit.precision, 3 / 5)
        self.assertAlmostEqual(legit.recall, 3 / 4)
        self.assertAlmostEqual(spam.precision, 2 / 3)
        self.assertAlmostEqual(spam.recall, 2 / 3)
        self.assertAlmostEqual(phish.precision, 1.0)
        self.assertAlmostEqual(phish.recall, 2 / 3)
        self.assertAlmostEqual(phish.f1, 0.8)
        self.assertEqual((legit.support, spam.support, phish.support), (4, 3, 3))
        self.assertAlmostEqual(m.macro_avg["recall"], (3 / 4 + 2 / 3 + 2 / 3) / 3)
        self.assertAlmostEqual(m.weighted_avg["recall"], (3 / 4 * 4 + 2 / 3 * 3 + 2 / 3 * 3) / 10)

    def test_perfect_predictions(self):
        y = ["spam", "phishing", "legitimate"] * 2
        m = compute_metrics(y, y)
        self.assertEqual(m.accuracy, 1.0)
        self.assertTrue(all(c.f1 == 1.0 for c in m.per_class.values()))

    def test_class_never_predicted_or_present_gives_zero_not_error(self):
        m = compute_metrics(["spam", "spam"], ["legitimate", "legitimate"])
        self.assertEqual(m.per_class["spam"].recall, 0.0)
        self.assertEqual(m.per_class["phishing"].precision, 0.0)  # no predictions, no support
        self.assertEqual(m.per_class["phishing"].f1, 0.0)

    def test_empty_input(self):
        m = compute_metrics([], [])
        self.assertEqual(m.total, 0)
        self.assertEqual(m.accuracy, 0.0)

    def test_validation(self):
        with self.assertRaises(ValueError):
            compute_metrics(["spam"], [])
        with self.assertRaises(ValueError):
            compute_metrics(["spam"], ["unknown"])

    def test_format_text_contains_key_sections(self):
        text = compute_metrics(["spam"], ["spam"]).format_text()
        for needle in ("Accuracy", "precision", "recall", "f1-score", "Confusion matrix"):
            self.assertIn(needle, text)

    def test_evaluate_results_skips_unlabelled_and_errors(self):
        results = [res("spam", "spam"), res(None, "spam"), res("phishing", "error"), res("legitimate", "spam")]
        report = evaluate_results(results)
        self.assertEqual(report.total, 2)
        self.assertEqual(report.skipped, 2)
        self.assertAlmostEqual(report.accuracy, 0.5)

    def test_evaluate_results_none_when_nothing_labelled(self):
        self.assertIsNone(evaluate_results([res(None, "spam")]))


if __name__ == "__main__":
    unittest.main()

import unittest

from bot.brand import CORE_PROMPT
from bot.formatting import tidy_answer, to_html


class TidyAnswerTests(unittest.TestCase):
    def test_strips_opening_filler_en(self):
        self.assertEqual(tidy_answer("Sure! here is the answer about open ports on your server."),
                         "Here is the answer about open ports on your server.")

    def test_strips_opening_and_closing_ar(self):
        out = tidy_answer("بالتأكيد! إليك الشرح الكامل للثغرة وتأثيرها.\n\n**⚠️ الأثر**\n- شيء\n\n"
                          "أتمنى أن يكون هذا مفيداً، لا تتردد في السؤال.")
        self.assertTrue(out.startswith("إليك"))
        self.assertNotIn("لا تتردد", out)

    def test_keeps_short_or_code_answers(self):
        self.assertEqual(tidy_answer("Sure."), "Sure.")
        code = "```py\nprint(1)\n```"
        self.assertEqual(tidy_answer(code), code)

    def test_never_empties_text(self):
        self.assertTrue(tidy_answer("Okay.\n").strip())

    def test_to_html_uses_tidy(self):
        self.assertNotIn("hope this helps", to_html("The port is open and exposed to the internet.\n\nI hope this helps!"))

    def test_prompt_has_quality_rules(self):
        self.assertIn("ANSWER QUALITY", CORE_PROMPT)
        self.assertIn("Confidence", CORE_PROMPT)


if __name__ == "__main__":
    unittest.main()

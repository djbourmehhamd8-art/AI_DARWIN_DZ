"""v4.9.1: ReDoS sandbox, complex-number calc result, JSON depth bound, Python<3.12 syntax, malformed-URL domains."""
import time
import unittest

from bot import netintel, proutils as P
from bot.security import ports


class Hardening491(unittest.TestCase):
    def test_catastrophic_regex_is_stopped_not_hung(self):
        t = time.time()
        with self.assertRaises(ValueError):
            P.regex_test(r"(a?){28}a{28} :: " + "a" * 28)       # slips past the nested-quantifier filter
        self.assertLess(time.time() - t, 6)
        with self.assertRaises(ValueError):
            P.regex_test(r"a*a*a*a*a*a*a*b :: " + "a" * 300)

    def test_regex_still_works(self):
        r = P.regex_test(r"(\d+)-(\w+) :: 12-ab 3-x")
        self.assertEqual(r["count"], 2)
        self.assertEqual(r["matches"][0]["groups"], ["12", "ab"])
        with self.assertRaises(ValueError):
            P.regex_test("(unclosed :: x")

    def test_calc_never_returns_complex(self):
        with self.assertRaises(ValueError):
            P.calc("(-8)**0.5")
        self.assertEqual(P.calc("2**10"), 1024)

    def test_json_depth_bound_is_explicit(self):
        with self.assertRaises(ValueError):
            P.json_pretty("[" * 300 + "]" * 300)
        self.assertEqual(P.json_pretty('{"a":["]]]",{"b":1}]}')["type"], "dict")

    def test_ports_describe_has_no_backslash_in_fstring_expression(self):
        with open(ports.__file__, encoding="utf-8") as source:
            src = source.read()
        compile(src, ports.__file__, "exec")                       # py3.9-3.11 would raise SyntaxError on the old code
        self.assertTrue(ports.describe([(22, ("SSH", "low", "x", "y"))], "en"))

    def test_valid_domain_rejects_malformed_urls(self):
        for bad in ("http://[abc", "http://[::1]x/"):
            self.assertIsNone(netintel.valid_domain(bad))


if __name__ == "__main__":
    unittest.main()

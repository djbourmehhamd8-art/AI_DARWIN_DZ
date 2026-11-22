import base64
import json
import time
import unittest

from bot.security import hashing, ioc, jwt_tool, mailheaders, password, urlcheck
from bot.security.secrets_guard import redact


class IocTest(unittest.TestCase):
    def test_extract_and_refang(self):
        r = ioc.extract("hxxps://evil[.]com/a, 8.8.8.8, 999.1.1.1, main.py, a@b.com, CVE-2024-3094 " + "a" * 64)
        self.assertEqual(r["urls"], ["https://evil.com/a"])
        self.assertEqual(r["ips"], ["8.8.8.8"])
        self.assertEqual(r["domains"], ["evil.com"])
        self.assertEqual(r["emails"], ["a@b.com"])
        self.assertEqual(r["cves"], ["CVE-2024-3094"])
        self.assertEqual(len(r["sha256"]), 1)
        self.assertEqual(r["md5"], [])

    def test_defang(self):
        self.assertEqual(ioc.defang("https://evil.com/x"), "hxxps[:]//evil[.]com/x")


class UrlTest(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(urlcheck.analyze("https://www.paypal.com/")["level"], "low")
        bad = urlcheck.analyze("http://paypa1-secure-login.tk/verify")
        self.assertIn("brand_spoof", bad["findings"])
        self.assertIn(bad["level"], ("high", "critical"))
        self.assertIn("userinfo", urlcheck.analyze("https://google.com@evil.ru/")["findings"])
        self.assertIn("punycode", urlcheck.analyze("http://xn--pple-43d.com")["findings"])
        self.assertNotIn("hyphens", urlcheck.analyze("http://xn--pple-43d.com")["findings"])
        self.assertIn("ip_host", urlcheck.analyze("http://10.0.0.1:8081/a.exe")["findings"])
        self.assertEqual(urlcheck.analyze("javascript:alert(1)")["level"], "high")

    def test_describe_is_defanged(self):
        txt = urlcheck.describe(urlcheck.analyze("http://evil.tk/login"), "en")
        self.assertIn("hxxp", txt)
        self.assertNotIn("http://evil.tk", txt)


class PasswordTest(unittest.TestCase):
    def test_strength(self):
        self.assertEqual(password.analyze("password1")["score"], 0)
        self.assertGreaterEqual(password.analyze(password.generate(20))["score"], 3)

    def test_generate_classes(self):
        for _ in range(20):
            p = password.generate(12)
            self.assertTrue(any(c.islower() for c in p) and any(c.isupper() for c in p)
                            and any(c.isdigit() for c in p) and any(not c.isalnum() for c in p))

    def test_pwned_k_anonymity(self):
        import hashlib
        h = hashlib.sha1(b"hunter2").hexdigest().upper()
        seen = []

        def fetch(prefix):
            seen.append(prefix)
            return f"AAAAA:1\n{h[5:]}:42\n"
        self.assertEqual(password.pwned_count("hunter2", fetch), 42)
        self.assertEqual(seen, [h[:5]])                       # only 5 chars are ever sent
        self.assertEqual(password.pwned_count("hunter2", lambda p: "ZZZ:1"), 0)
        self.assertEqual(password.pwned_count("x", lambda p: 1 / 0), -1)


class HashTest(unittest.TestCase):
    def test_identify(self):
        self.assertIn("MD5", hashing.identify("5f4dcc3b5aa765d61d8327deb882cf99"))
        self.assertEqual(hashing.identify("$2b$12$" + "a" * 53), ["bcrypt"])
        self.assertEqual(hashing.identify("hello world"), [])

    def test_digests_and_b64(self):
        self.assertEqual(hashing.digests("a")["md5"], "0cc175b9c0f1b6a831c399e269772661")
        self.assertEqual(hashing.b64_decode(hashing.b64_encode("مرحبا")), "مرحبا")


def _b(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


class JwtTest(unittest.TestCase):
    def test_flags(self):
        r = jwt_tool.inspect(_b({"alg": "none"}) + "." + _b({"sub": "1"}) + ".")
        self.assertTrue(r["ok"])
        for f in ("alg_none", "no_sig", "no_exp"):
            self.assertIn(f, r["flags"])
        now = time.time()
        r = jwt_tool.inspect("Bearer " + _b({"alg": "HS256"}) + "." + _b({"exp": now - 10, "aud": "a", "iss": "b"}) + ".sig")
        self.assertIn("expired", r["flags"])
        self.assertIn("hs_shared", r["flags"])
        self.assertFalse(jwt_tool.inspect("not.a.jwt")["ok"])


class HeadersTest(unittest.TestCase):
    RAW = ("From: \"ceo@corp.com\" <x@evil.ru>\nReply-To: boss@gmail.com\nReturn-Path: <b@mailer.xyz>\n"
           "Received: from a.b ([1.2.3.4]) by mx\nAuthentication-Results: mx; spf=fail; dkim=none; dmarc=fail\n"
           "Message-ID: <abc@mailer.xyz>\nSubject: Urgent\n")

    def test_flags(self):
        r = mailheaders.analyze(self.RAW)
        for f in ("spf_fail", "dkim_bad", "dmarc_bad", "reply_mismatch", "display_spoof"):
            self.assertIn(f, r["flags"])
        self.assertEqual(r["origin_ip"], "1.2.3.4")
        self.assertFalse(mailheaders.analyze("")["ok"])


class SecretsTest(unittest.TestCase):
    def test_redact(self):
        tok = "123456789:AAH" + "a" * 32
        text, kinds = redact(f"k AKIAABCDEFGHIJKLMNOP password=Sup3rSecret! postgres://u:hunter22@db/x {tok}")
        for bad in ("AKIAABCDEFGHIJKLMNOP", "Sup3rSecret!", "hunter22", tok):
            self.assertNotIn(bad, text)
        self.assertEqual(kinds, ["aws_key", "db_url_password", "secret_assignment", "telegram_token"])
        self.assertEqual(redact("nothing secret here"), ("nothing secret here", []))


if __name__ == "__main__":
    unittest.main()

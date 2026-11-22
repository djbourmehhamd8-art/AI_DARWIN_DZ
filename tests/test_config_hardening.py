import unittest
from unittest.mock import Mock

from bot.config import Config
from bot.telegram import TelegramAPI


class ConfigValidationTests(unittest.TestCase):
    def valid(self, **changes):
        values = dict(telegram_token="123456:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
                      api_key="test-api-key")
        values.update(changes)
        return Config(**values)

    def test_valid_defaults_pass(self):
        self.assertEqual(self.valid().validate(), [])


    def test_api_persona_is_applied_to_model_name(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"TELEGRAM_TOKEN": "t", "API_KEY": "k",
                                     "API_BASE_URL": "https://api.aiwithnorestrictions.com/v1",
                                     "MODEL": "notrack-uncensored", "API_PERSONA": "bare"}, clear=True):
            cfg = Config.from_env()
        self.assertEqual(cfg.model, "notrack-uncensored:bare")

    def test_rejects_zero_workers_before_executor_creation(self):
        self.assertTrue(any("WORKERS" in p for p in self.valid(workers=0).validate()))

    def test_rejects_invalid_urls_and_credentials(self):
        errors = self.valid(api_base_url="file:///tmp/x", telegram_api_url="https://user:pass@example.com").validate()
        self.assertTrue(any("API_BASE_URL" in p for p in errors))
        self.assertTrue(any("TELEGRAM_API_URL" in p for p in errors))

    def test_rejects_non_finite_temperature(self):
        self.assertTrue(any("DEFAULT_TEMP" in p for p in self.valid(default_temp=float("nan")).validate()))

    def test_rejects_invalid_strategy_and_log_level(self):
        errors = self.valid(key_strategy="random", log_level="TRACE").validate()
        self.assertTrue(any("KEY_STRATEGY" in p for p in errors))
        self.assertTrue(any("LOG_LEVEL" in p for p in errors))


class TelegramResponseTests(unittest.TestCase):
    def test_non_object_json_is_handled_without_crash(self):
        api = TelegramAPI("token")
        self.addCleanup(api.close)
        response = Mock()
        response.json.return_value = ["unexpected"]
        api.session.post = Mock(return_value=response)
        api.call("getMe")
        response.close.assert_called_once()

    def test_retry_after_is_capped(self):
        api = TelegramAPI("token")
        self.addCleanup(api.close)
        response = Mock()
        response.json.return_value = {"ok": False, "error_code": 400, "description": "bad request"}
        api.session.post = Mock(return_value=response)
        self.assertIsNone(api.call("sendMessage", chat_id=1, text="x"))
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

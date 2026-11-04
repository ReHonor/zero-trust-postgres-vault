"""Focused regression tests: outages and SQL errors must never count as blocked attacks."""
import unittest
from unittest.mock import MagicMock, patch
import engine


class Failure(Exception):
    def __init__(self, code):
        self.pgcode = code


class EngineTests(unittest.TestCase):
    def test_catalog_has_38_unique_implementations(self):
        self.assertEqual(len(engine.CAPABILITIES), 38)

    def test_privilege_error_is_expected_denial(self):
        self.assertTrue(engine.denied(Failure("42501")))

    def test_outage_is_not_permission_denial(self):
        self.assertFalse(engine.denied(Failure("08006")))

    def test_syntax_error_is_not_permission_denial(self):
        self.assertFalse(engine.denied(Failure("42601")))

    def test_wrong_password_has_specific_classifier(self):
        self.assertTrue(engine.authentication_failure(Exception("password authentication failed for user")))
        self.assertFalse(engine.authentication_failure(Exception("connection timed out")))

    def actor(self):
        actor = MagicMock()
        actor.credentials.return_value = {"data": {"username": "test-user"}}
        conn = actor.connect.return_value
        cur = conn.cursor.return_value.__enter__.return_value
        cur.description = None
        cur.statusmessage = "UPDATE 1"
        return actor, conn, cur

    def test_allowed_write_is_rolled_back(self):
        actor, conn, _ = self.actor()
        out = engine.sql_attempt(actor, ["UPDATE orders SET amount_mad=1"])
        self.assertEqual(out["outcome"], "allowed")
        conn.rollback.assert_called_once()
        conn.close.assert_called_once()

    def test_unexpected_attack_success_is_rolled_back(self):
        actor, conn, _ = self.actor()
        out = engine.sql_attempt(actor, ["DELETE FROM orders"], True)
        self.assertEqual(out["outcome"], "unexpected")
        conn.rollback.assert_called_once()

    def test_network_error_is_error_not_blocked(self):
        actor, conn, cur = self.actor()
        cur.execute.side_effect = Failure("08006")
        out = engine.sql_attempt(actor, ["DELETE FROM orders"], True)
        self.assertEqual(out["outcome"], "error")
        conn.rollback.assert_called_once()

    def test_privilege_denial_is_blocked_and_rolled_back(self):
        actor, conn, cur = self.actor()
        cur.execute.side_effect = [None, Failure("42501")]
        out = engine.sql_attempt(actor, ["DELETE FROM orders"], True)
        self.assertEqual(out["outcome"], "blocked")
        conn.rollback.assert_called_once()

    def test_setup_denial_is_not_counted_as_target_denial(self):
        actor, conn, cur = self.actor()
        cur.execute.side_effect = Failure("42501")
        out = engine.sql_attempt(actor, ["DELETE FROM orders"], True)
        self.assertEqual(out["outcome"], "error")
        conn.rollback.assert_called_once()

    def test_unknown_case_does_not_contact_services(self):
        broker = MagicMock()
        out = engine.run(broker, "arbitrary SQL", "test", lambda text: None)
        self.assertEqual(out["outcome"], "error")
        broker.login.assert_not_called()


if __name__ == "__main__":
    unittest.main()

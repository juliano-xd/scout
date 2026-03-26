import unittest
from semantic_engine import SemanticEngine

class TestObfuscationResilience(unittest.TestCase):
    def setUp(self):
        self.engine = SemanticEngine()

    def test_messy_labels(self):
        """Test reconstruction with labels that have unusual characters (obfuscation)."""
        body = [
            "if-eqz v0, :label_#$%^",
            "const/4 v1, 0x1",
            "goto :label_*)@!",
            ":label_#$%^",
            "const/4 v1, 0x0",
            ":label_*)@!",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIn("if (v0 == 0) {", translation)
        self.assertIn("v1 = 0x0", translation) # Proof that else branch or label branch was followed

    def test_malformed_bytecode_graceful_fail(self):
        """Test engine stability when encountering incomplete methods or missing tables."""
        body = [
            ".method public broken()V",
            "const/4 v0, 0x1",
            # Missing .end method and labels
        ]
        # Should NOT crash
        try:
            translation = self.engine.translate_method(body, {})
            self.assertIsInstance(translation, str)
        except Exception as e:
            self.fail(f"SemanticEngine crashed on malformed input: {e}")

if __name__ == "__main__":
    unittest.main()


class TestSemanticEdgeCases(unittest.TestCase):
    """Test semantic engine edge cases."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_empty_method(self):
        """Test translation of empty method."""
        body = [
            ".method public empty()V",
            "return-void",
            ".end method"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_single_instruction(self):
        """Test translation with single instruction."""
        body = ["const/4 v0, 0x1"]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_void_return(self):
        """Test void return translation."""
        body = ["return-void"]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)


class TestCFGEdgeCases(unittest.TestCase):
    """Test CFG edge cases."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_unreachable_code(self):
        """Test CFG with unreachable code."""
        body = [
            "const/4 v0, 0x1",
            "goto :end",
            "const/4 v1, 0x2",
            ":end",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_multiple_returns(self):
        """Test multiple return paths."""
        body = [
            "if-eqz v0, :else",
            "return-void",
            ":else",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)


if __name__ == "__main__":
    unittest.main()

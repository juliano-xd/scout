import unittest
from semantic_engine import SemanticEngine

class TestSemanticEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SemanticEngine()

    def test_try_catch_reconstruction(self):
        """Verify reconstruction of try-catch blocks in pseudocode."""
        body = [
            ":try_start_0",
            "invoke-virtual {v0}, Ljava/io/File;->delete()Z",
            ":try_end_0",
            ".catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :handler_0",
            ":handler_0",
            "move-exception v1",
            "return-void"
        ]
        # In actual engine, this needs dfa_results but let's test the block logic
        translation = self.engine.translate_method(body, {})
        self.assertIn("try {", translation)
        self.assertIn("catch (Ljava/io/IOException;)", translation)

    def test_switch_case_reconstruction(self):
        """Verify reconstruction of switch blocks."""
        body = [
            "packed-switch v0, :pswitch_data_0",
            ":pswitch_0",
            "const/4 v1, 0x1",
            "goto :pswitch_end",
            ":pswitch_1",
            "const/4 v1, 0x2",
            ":pswitch_end",
            "return-void",
            ":pswitch_data_0",
            ".packed-switch 0x1",
            ":pswitch_0",
            ":pswitch_1",
            ".end packed-switch"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIn("switch(v0) {", translation)
        self.assertIn("case 1:", translation)
        self.assertIn("case 2:", translation)

if __name__ == "__main__":
    unittest.main()

import unittest
from semantic_engine import SemanticEngine
from tests.utils import SmaliFactory

class TestSemanticAdvanced(unittest.TestCase):
    def setUp(self):
        self.engine = SemanticEngine()

    def test_multi_handler_catch(self):
        """Verify reconstruction of a try block with multiple catch handlers."""
        body = [
            ":try_start_0",
            "invoke-static {}, Lcom/app/IO;->read()V",
            ":try_end_0",
            ".catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :handler_io",
            ".catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :handler_gen",
            ":handler_io",
            "move-exception v0",
            "return-void",
            ":handler_gen",
            "move-exception v0",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIn("catch (Ljava/io/IOException;)", translation)
        self.assertIn("catch (Ljava/lang/Exception;)", translation)
        self.assertEqual(translation.count("catch ("), 2)

    def test_nested_try_in_switch(self):
        """Verify reconstruction of a try block nested inside a switch case."""
        body = [
            "sparse-switch v0, :sswitch_data",
            ":case_1",
            ":try_start_0",
            "invoke-static {}, Lcom/app/IO;->do()V",
            ":try_end_0",
            ".catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :handler",
            "goto :end",
            ":handler",
            "return-void",
            ":end",
            "return-void",
            ":sswitch_data",
            ".sparse-switch 0x1",
            ":case_1",
            ".end sparse-switch"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIn("switch(v0) {", translation)
        self.assertIn("case", translation)
        self.assertIn("try {", translation)
        self.assertIn("try {", translation)
        # Ensure 'try' is inside 'case 1' (heuristic check by order)
        case_idx = translation.find("case 1:")
        try_idx = translation.find("try {")
        self.assertGreater(try_idx, case_idx)

if __name__ == "__main__":
    unittest.main()


class TestSemanticComplexFlows(unittest.TestCase):
    """Test complex semantic flows."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_while_loop(self):
        """Test while loop translation."""
        body = [
            "const/4 v0, 0x0",
            ":loop_start",
            "if-ge v0, v1, :loop_end",
            "add-int/lit8 v0, v0, 0x1",
            "goto :loop_start",
            ":loop_end",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)
        self.assertIn("if", translation.lower())

    def test_do_while(self):
        """Test do-while loop translation."""
        body = [
            ":do_start",
            "add-int/lit8 v0, v0, 0x1",
            "if-lt v0, v1, :do_start",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_for_loop(self):
        """Test for-like loop translation."""
        body = [
            "const/4 v0, 0x0",
            ":for_start",
            "if-ge v0, v1, :for_end",
            "add-int/lit8 v0, v0, 0x1",
            "goto :for_start",
            ":for_end",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)


class TestSemanticArrays(unittest.TestCase):
    """Test array handling in semantic engine."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_array_creation(self):
        """Test array creation translation."""
        body = [
            "const/4 v0, 0x5",
            "new-array v1, v0, [I",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_array_element_access(self):
        """Test array element access translation."""
        body = [
            "aget v0, v1, v2",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_array_element_write(self):
        """Test array element write translation."""
        body = [
            "aput v0, v1, v2",
            "return-void"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)


class TestSemanticTypes(unittest.TestCase):
    """Test type handling in semantic engine."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_object_type(self):
        """Test object type translation."""
        body = [
            "new-instance v0, Ljava/lang/String;",
            "return-object v0"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_primitive_types(self):
        """Test primitive types translation."""
        body = [
            "const/4 v0, 0x1",
            "return v0"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)

    def test_array_type(self):
        """Test array type translation."""
        body = [
            "const/4 v0, 0x3",
            "new-array v1, v0, [B",
            "return-object v1"
        ]
        translation = self.engine.translate_method(body, {})
        self.assertIsInstance(translation, str)


if __name__ == "__main__":
    unittest.main()

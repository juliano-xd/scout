import unittest
from frida_engine import FridaEngine

class TestFridaEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FridaEngine(None)

    def test_type_mapping(self):
        """Verify JVM descriptor to Frida/Java type conversion."""
        self.assertEqual(self.engine.parse_smali_types("Z")[0], "boolean")
        self.assertEqual(self.engine.parse_smali_types("Ljava/lang/String;")[0], "java.lang.String")
        self.assertEqual(self.engine.parse_smali_types("[B")[0], "[B")
        # Complex multidimensional array
        self.assertEqual(self.engine.parse_smali_types("[[Ljava/lang/Object;")[0], "[[Ljava.lang.Object;")

    def test_hook_generation_script(self):
        """Verify generated Frida script structure."""
        script = self.engine.generate_script("Lcom/app/Net;->send([B)Z")
        self.assertIsNotNone(script)
        self.assertIsInstance(script, str)
        self.assertIn("Java.use", script)

if __name__ == "__main__":
    unittest.main()


class TestFridaEngineAdvanced(unittest.TestCase):
    """Advanced Frida engine tests."""

    def setUp(self):
        self.engine = FridaEngine(None)

    def test_void_type(self):
        """Test void type parsing."""
        result = self.engine.parse_smali_types("V")
        self.assertIsInstance(result, list)

    def test_primitive_types(self):
        """Test primitive type parsing."""
        self.assertEqual(self.engine.parse_smali_types("I")[0], "int")
        self.assertEqual(self.engine.parse_smali_types("J")[0], "long")
        self.assertEqual(self.engine.parse_smali_types("F")[0], "float")
        self.assertEqual(self.engine.parse_smali_types("D")[0], "double")
        self.assertEqual(self.engine.parse_smali_types("B")[0], "byte")
        self.assertEqual(self.engine.parse_smali_types("S")[0], "short")
        self.assertEqual(self.engine.parse_smali_types("C")[0], "char")

    def test_array_type(self):
        """Test array type parsing."""
        result = self.engine.parse_smali_types("[I")
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    def test_hook_static_method(self):
        """Test hook generation for static method."""
        script = self.engine.generate_script("Lcom/app/Utils;->staticMethod()V")
        self.assertIsInstance(script, str)

    def test_hook_constructor(self):
        """Test hook generation for constructor."""
        script = self.engine.generate_script("Lcom/app/Object;-><init>()V")
        self.assertIsInstance(script, str)


class TestFridaHooks(unittest.TestCase):
    """Test Frida hook generation."""

    def setUp(self):
        self.engine = FridaEngine(None)

    def test_multiple_overloads(self):
        """Test hook with multiple overloads."""
        script = self.engine.generate_script("Lcom/app/calc;->add(II)I")
        self.assertIn("Java.use", script)

    def test_return_type_handling(self):
        """Test return type handling in hook."""
        script = self.engine.generate_script("Lcom/app/Net;->getData()[B")
        self.assertIsInstance(script, str)


if __name__ == "__main__":
    unittest.main()

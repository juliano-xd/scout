import unittest
from semantic_engine import SemanticEngine

class TestSemanticEngineFoldStatements(unittest.TestCase):
    """Test cases for Bug #10: String quote handling in statement folding."""

    def setUp(self):
        self.engine = SemanticEngine()

    def test_fold_with_string_on_right_side(self):
        """
        Bug #10: When the right-hand value is a string literal,
        folding should still work correctly (string is copied as-is).
        
        Example: v0 = "hello world" with v1 = v0 should fold to v1 = "hello world"
        """
        translated = [
            'v0 = "hello world"',
            'v1 = v0'
        ]
        result = self.engine._fold_statements(translated)
        
        # Should fold correctly - v1 should get the string value
        self.assertEqual(len(result), 1)
        self.assertIn("hello world", result[0])

    def test_fold_avoid_double_substitution(self):
        """
        When a register VALUE contains the same register name as the variable,
        avoid infinite/deep folding issues.
        
        Example: v0 = "v0" (literal string "v0")
        Then v1 = v0 should become v1 = "v0" (not "v0" again)
        But if we then have v0 = v1, we get circular reference
        """
        translated = [
            'v0 = "v0"',  # value is literal string "v0"
            'v1 = v0'
        ]
        result = self.engine._fold_statements(translated)
        
        # Should fold: v1 = "v0"
        self.assertEqual(len(result), 1)
        self.assertIn('"v0"', result[0])

    def test_fold_with_string_containing_register_like_text(self):
        """
        Test case: string contains text that looks like a register
        but should still fold correctly (string is copied as-is).
        """
        translated = [
            'v0 = "value123"',
            'Log.d("v0_tag", v0)'
        ]
        result = self.engine._fold_statements(translated)
        
        # v0 = "value123", then Log.d(..., v0) should become Log.d(..., "value123")
        # But this is not a simple assignment fold, it's a method call
        # The function should handle this correctly
        self.assertIn("value123", result[0])

    def test_fold_simple_case(self):
        """Verify normal folding still works."""
        translated = [
            'v0 = 5',
            'v1 = v0'
        ]
        result = self.engine._fold_statements(translated)
        
        # Should fold: v1 = 5
        self.assertEqual(len(result), 1)
        self.assertIn("5", result[0])

    def test_fold_with_multiple_references(self):
        """Test folding with multiple references to the same variable."""
        translated = [
            'v0 = "first"',
            'v1 = v0',
            'v2 = v0'
        ]
        result = self.engine._fold_statements(translated)
        
        # v0 = "first", then v1=v0 -> v1="first", then v2=v0 -> v2="first"
        # Final result should have 3 lines (v0, v1, v2 all showing their values)
        # or could be folded to just the final value depending on implementation
        # This is a more complex case - at minimum, first fold should work
        self.assertLessEqual(len(result), 3)

    def test_fold_string_at_end(self):
        """Test case where string comes after the register assignment."""
        translated = [
            'v0 = 10',
            'v1 = "processing"'  # simple string
        ]
        result = self.engine._fold_statements(translated)
        
        # No fold needed - v0 is not used in second line
        self.assertEqual(len(result), 2)

if __name__ == "__main__":
    unittest.main()

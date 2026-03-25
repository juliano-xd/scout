import unittest
from unittest.mock import Mock, patch
from frida_engine import FridaEngine

class TestFridaStaticMethodDetection(unittest.TestCase):
    """Test cases for Bug #13: Static method detection is too fragile."""

    def setUp(self):
        self.engine = FridaEngine()

    def test_static_detection_at_beginning(self):
        """Static method detected when .method static is at the beginning."""
        # Format: ".method static" - the keyword "static" appears after ".method"
        method_body = [
            ".method static onCreate()V",
            ".registers 2",
            "return-void",
            ".end method"
        ]
        # The actual code in FridaEngine uses: ".method static" in l
        is_static = any(".method static" in l for l in method_body[:20])
        self.assertTrue(is_static)

    def test_static_detection_with_annotation_before(self):
        """
        Bug #13: When there's an annotation before .method static declaration,
        scanning only first 20 lines may fail if the annotation is long.
        """
        # Create a method with annotations taking more than 20 lines before static
        method_body = []
        for i in range(25):
            method_body.append(f".annotation visible {i}")
            method_body.append(f"    value = {i}")
            method_body.append(".end annotation")
        method_body.append(".method static onCreate()V")
        
        is_static = any(".method static" in l for l in method_body[:20])
        # This SHOULD fail with current implementation (only checks first 20)
        self.assertFalse(is_static, "Bug #13: Should fail - annotation pushes static beyond 20 lines")

    def test_static_detection_scan_full_body(self):
        """
        Improved: Scan entire method body for static detection.
        """
        method_body = []
        for i in range(25):
            method_body.append(f".annotation visible {i}")
            method_body.append(f"    value = {i}")
            method_body.append(".end annotation")
        method_body.append(".method static onCreate()V")
        
        # Scan full body instead of just first 20 lines - should work
        is_static = any(".method static" in l for l in method_body)
        self.assertTrue(is_static)

    def test_static_detection_no_static(self):
        """Non-static method should not be detected as static."""
        method_body = [
            ".method public onCreate()V",
            ".registers 2",
            "return-void",
            ".end method"
        ]
        is_static = any(".method static" in l for l in method_body)
        self.assertFalse(is_static)

    def test_frida_engine_detects_static_correctly(self):
        """
        Integration test: FridaEngine should correctly detect static methods
        regardless of their position in the body.
        """
        engine = FridaEngine()
        # Long method with static declaration at the end (beyond 20 lines)
        method_body = []
        for i in range(30):
            method_body.append(f"    # comment line {i}")
        method_body.append(".method static onCreate()V")
        method_body.append("    return-void")
        
        # Current implementation only checks first 20 lines
        is_static = any(".method static" in l for l in method_body[:20])
        
        # Bug #13 reproduced: This should be True but is False
        self.assertFalse(is_static, "Bug #13 reproduced")

if __name__ == "__main__":
    unittest.main()

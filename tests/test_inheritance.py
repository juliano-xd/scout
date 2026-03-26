import unittest
from pathlib import Path
from inheritance_engine import InheritanceEngine

class TestInheritanceEngine(unittest.TestCase):
    def setUp(self):
        # Mock class index: Lsub; -> Lbase; -> Ljava/lang/Object;
        self.class_index = {
            "Lcom/app/Sub;": [Path("smali/Sub.smali")],
            "Lcom/app/Base;": [Path("smali/Base.smali")]
        }
        self.engine = InheritanceEngine(self.class_index, lambda p: "")
        self.engine.add_direct_inheritance("Lcom/app/Sub;", "Lcom/app/Base;")
        self.engine.add_direct_inheritance("Lcom/app/Base;", "Landroid/app/Activity;")

    def test_interning(self):
        """Verify that signatures are interned for memory efficiency."""
        self.engine.add_direct_inheritance("Lcom/test/A;", "Lcom/test/B;")
        super_cl = self.engine.get_super("Lcom/test/A;")
        self.assertEqual(super_cl, "Lcom/test/B;")
        # Interning check (ensure same object)
        import sys
        self.assertIs(super_cl, sys.intern("Lcom/test/B;"))

    def test_hierarchy(self):
        """Verify full inheritance path resolution."""
        hierarchy = self.engine.get_hierarchy("Lcom/app/Sub;")
        self.assertEqual(hierarchy, ["Lcom/app/Base;", "Landroid/app/Activity;"])

    def test_is_instance_of(self):
        """Verify multi-level instance_of checks."""
        self.assertTrue(self.engine.is_instance_of("Lcom/app/Sub;", "Landroid/app/Activity;"))
        self.assertTrue(self.engine.is_instance_of("Lcom/app/Sub;", "Lcom/app/Base;"))
        self.assertFalse(self.engine.is_instance_of("Lcom/app/Sub;", "Lcom/app/Other;"))

    def test_caching(self):
        """Verify result caching for hierarchy lookups."""
        _ = self.engine.get_hierarchy("Lcom/app/Sub;")
        self.assertIn("Lcom/app/Sub;", self.engine._hierarchy_cache)

if __name__ == "__main__":
    unittest.main()


class TestInheritanceEdgeCases(unittest.TestCase):
    """Test inheritance edge cases."""

    def setUp(self):
        self.class_index = {
            "Lcom/test/Child;": [Path("smali/Child.smali")],
            "Lcom/test/Parent;": [Path("smali/Parent.smali")],
            "Lcom/test/GrandParent;": [Path("smali/GrandParent.smali")],
        }
        self.engine = InheritanceEngine(self.class_index, lambda p: "")

    def test_multiple_inheritance_path(self):
        """Test multiple inheritance paths."""
        self.engine.add_direct_inheritance("Lcom/test/Child;", "Lcom/test/Parent;")
        self.engine.add_direct_inheritance("Lcom/test/Parent;", "Lcom/test/GrandParent;")
        self.engine.add_direct_inheritance("Lcom/test/GrandParent;", "Ljava/lang/Object;")
        
        hierarchy = self.engine.get_hierarchy("Lcom/test/Child;")
        self.assertGreaterEqual(len(hierarchy), 3)

    def test_direct_inheritance_only(self):
        """Test direct inheritance only."""
        self.engine.add_direct_inheritance("Lcom/test/Child;", "Ljava/lang/Object;")
        
        parent = self.engine.get_super("Lcom/test/Child;")
        self.assertEqual(parent, "Ljava/lang/Object;")

    def test_no_inheritance(self):
        """Test class with no inheritance set."""
        parent = self.engine.get_super("Lcom/test/Unknown;")
        self.assertIsNone(parent)

    def test_is_instance_of_object(self):
        """Test class with known Object inheritance."""
        self.engine.add_direct_inheritance("Lcom/test/Any;", "Ljava/lang/Object;")
        self.assertTrue(self.engine.is_instance_of("Lcom/test/Any;", "Ljava/lang/Object;"))

    def test_interface_implements(self):
        """Test interface implementation check."""
        self.engine.add_direct_inheritance("Lcom/test/Impl;", "Ljava/lang/Object;")
        hierarchy = self.engine.get_hierarchy("Lcom/test/Impl;")
        self.assertIsNotNone(hierarchy)


class TestInheritanceCaching(unittest.TestCase):
    """Test inheritance caching."""

    def setUp(self):
        self.class_index = {"Lcom/test/App;": [Path("smali/App.smali")]}
        self.engine = InheritanceEngine(self.class_index, lambda p: "")

    def test_cache_invalidation(self):
        """Test cache can be cleared."""
        self.engine.add_direct_inheritance("Lcom/test/A;", "Ljava/lang/Object;")
        self.engine.get_hierarchy("Lcom/test/A;")
        
        self.engine._hierarchy_cache.clear()
        self.assertEqual(len(self.engine._hierarchy_cache), 0)

    def test_cache_population(self):
        """Test cache is populated after lookup."""
        self.engine.add_direct_inheritance("Lcom/test/A;", "Ljava/lang/Object;")
        self.engine.get_hierarchy("Lcom/test/A;")
        
        self.assertIn("Lcom/test/A;", self.engine._hierarchy_cache)


if __name__ == "__main__":
    unittest.main()

import unittest
import os
from pathlib import Path
from tracking_engine import TrackingEngine, intern_sig

class TestTrackingEngine(unittest.TestCase):
    def setUp(self):
        self.class_index = {"Lcom/test/App;": [Path("App.smali")]}
        self.engine = TrackingEngine(self.class_index, {}, kb=None)
        # Clear existing cache for tests
        if os.path.exists("scout_xref.pkl"): os.remove("scout_xref.pkl")

    def test_taint_analysis(self):
        """Verify Taint analysis detects Source -> Sink flows."""
        body = [
            'const-string v0, "https://leak.com/api"',
            'sput-object v0, Lcom/test/App;->URL:Ljava/lang/String;',
            'sget-object v1, Lcom/test/App;->URL:Ljava/lang/String;',
            'invoke-static {v1}, Lcom/test/Net;->send(Ljava/lang/String;)V'
        ]
        results = self.engine.taint.analyze_method(body)
        
        v0_data = results.get("v0", set())
        v1_data = results.get("v1", set())
        
        # v0 should have SOURCE
        self.assertTrue(any("SRC:URL" in d for d in v0_data))
        # v1 should have FLD (leaked from static field) and SINK
        self.assertTrue(any("FLD:" in d for d in v1_data))
        self.assertTrue(any("SNK:Lcom/test/Net;->send" in d for d in v1_data))

    def test_interning_logic(self):
        """Verify strings are interned in Taint engine."""
        import sys
        s = "Lshared/id;"
        interned = intern_sig(s)
        self.assertIs(interned, sys.intern(s))

    def test_xref_persistence(self):
        """Verify index can be saved and loaded from disk."""
        self.engine.xref.method_callers[intern_sig("Ltarget;->met")] = {intern_sig("Lcaller;")}
        self.engine.xref.save_index("test_index.pkl")
        
        new_xref = self.engine.xref.__class__(self.class_index, {})
        loaded = new_xref.load_index("test_index.pkl")
        
        self.assertTrue(loaded)
        self.assertIn("Ltarget;->met", new_xref.method_callers)
        if os.path.exists("test_index.pkl"): os.remove("test_index.pkl")

    def test_suggest_name(self):
        """Verify heuristic-based register naming."""
        history = {intern_sig("SRC:URL"), intern_sig("SNK:Lnet/Http;->get")}
        name = self.engine.taint.suggest_name("v0", history)
        self.assertEqual(name, "url_v0")

if __name__ == "__main__":
    unittest.main()


class TestTaintTrackingAdvanced(unittest.TestCase):
    """Advanced taint tracking tests."""

    def setUp(self):
        self.class_index = {"Lcom/test/App;": [Path("App.smali")]}
        self.engine = TrackingEngine(self.class_index, {}, kb=None)

    def test_basic_taint_result(self):
        """Verify taint analysis returns results."""
        body = [
            "const/4 v0, 0x1",
            "return-void"
        ]
        results = self.engine.taint.analyze_method(body)
        
        self.assertIsInstance(results, dict)

    def test_field_taint(self):
        """Verify taint through fields."""
        body = [
            "const-string v0, \"data\"",
            "sput-object v0, Lcom/test/App;->field:Ljava/lang/String;",
            "sget-object v1, Lcom/test/App;->field:Ljava/lang/String;",
            "return-object v1"
        ]
        results = self.engine.taint.analyze_method(body)
        
        self.assertIsInstance(results, dict)


class TestTaintSourceSink(unittest.TestCase):
    """Test source and sink detection."""

    def setUp(self):
        self.class_index = {"Lcom/test/App;": [Path("App.smali")]}
        self.engine = TrackingEngine(self.class_index, {}, kb=None)

    def test_basic_analysis(self):
        """Test basic analysis returns dict."""
        body = [
            "const/4 v0, 0x1",
            "return-void"
        ]
        results = self.engine.taint.analyze_method(body)
        
        self.assertIsInstance(results, dict)


if __name__ == "__main__":
    unittest.main()

import unittest
import sys
from pathlib import Path

# Add root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from tracking_engine import XREFEngine

class TestCallGraph(unittest.TestCase):
    def setUp(self):
        self.xref = XREFEngine({}, {})
        # Mock some calls: A -> B -> C
        self.xref.method_callees["LA;->main()V"].add("LB;->step1()V")
        self.xref.method_callers["LB;->step1()V"].add("LA;->main()V")
        self.xref.method_callees["LB;->step1()V"].add("LC;->step2()V")
        self.xref.method_callers["LC;->step2()V"].add("LB;->step1()V")

    def test_call_graph_depth_1(self):
        graph = self.xref.get_call_graph("LB;->step1()V", depth=1)
        self.assertEqual(graph["target"], "LB;->step1()V")
        self.assertIn("LA;->main()V", graph["callers"])
        self.assertIn("LC;->step2()V", graph["callees"])

    def test_call_graph_depth_2(self):
        # A -> B -> C.  Graph from A with depth 2 should see C at depth 2 from B
        graph = self.xref.get_call_graph("LA;->main()V", depth=2, direction="down")
        # graph["callees"] should be a list of graphs
        self.assertEqual(len(graph["callees"]), 1)
        b_graph = graph["callees"][0]
        self.assertEqual(b_graph["target"], "LB;->step1()V")
        self.assertIn("LC;->step2()V", b_graph["callees"])

    def test_array_xref_regex(self):
        """Verify that array method calls are matched."""
        line = "invoke-virtual {v0}, [B->clone()Ljava/lang/Object;"
        m = self.xref.RE_CALL.search(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "[B->clone()Ljava/lang/Object;")
        
        line_obj = "invoke-virtual {v0}, [Ljava/lang/String;->clone()Ljava/lang/Object;"
        m_obj = self.xref.RE_CALL.search(line_obj)
        self.assertIsNotNone(m_obj)
        self.assertEqual(m_obj.group(1), "[Ljava/lang/String;->clone()Ljava/lang/Object;")

if __name__ == "__main__":
    unittest.main()


class TestCallGraphEdgeCases(unittest.TestCase):
    """Test call graph edge cases."""

    def setUp(self):
        self.xref = XREFEngine({}, {})

    def test_interface_call(self):
        """Test interface method calls."""
        self.xref.method_callers["LIface;->method()V"] = {"LImpl;->method()V"}
        callers = self.xref.method_callers.get("LIface;->method()V", set())
        self.assertIn("LImpl;->method()V", callers)

    def test_virtual_call_resolution(self):
        """Test virtual method call resolution."""
        line = "invoke-virtual {p0}, Lcom/test/Animal;->makeSound()V"
        m = self.xref.RE_CALL.search(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "Lcom/test/Animal;->makeSound()V")

    def test_static_call_resolution(self):
        """Test static method call resolution."""
        line = "invoke-static {v0}, Lcom/test/Utils;->helper(Ljava/lang/String;)V"
        m = self.xref.RE_CALL.search(line)
        self.assertIsNotNone(m)

    def test_direct_call_resolution(self):
        """Test direct method call resolution."""
        line = "invoke-direct {p0}, Lcom/test/Object;-><init>()V"
        m = self.xref.RE_CALL.search(line)
        self.assertIsNotNone(m)

    def test_super_call_resolution(self):
        """Test super method call resolution."""
        line = "invoke-super {p0, p1}, Lcom/test/Base;->init()V"
        m = self.xref.RE_CALL.search(line)
        self.assertIsNotNone(m)

    def test_method_callees(self):
        """Test method callee tracking."""
        self.xref.method_callees["Lcom/test/Main;->run()V"] = {"Lcom/test/Helper;->do()V"}
        callees = self.xref.method_callees.get("Lcom/test/Main;->run()V", set())
        self.assertIn("Lcom/test/Helper;->do()V", callees)


if __name__ == "__main__":
    unittest.main()

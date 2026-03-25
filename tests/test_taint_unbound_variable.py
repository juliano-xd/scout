import unittest
from tracking_engine import TaintEngine

class TestTaintUnboundVariable(unittest.TestCase):
    """Test cases for Bug #9: last_invoke_sig possibly unbound."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_move_result_without_invoke(self):
        """
        Bug #9: If move-result appears without a preceding invoke,
        last_invoke_sig will be unbound.
        
        This simulates a method that starts with move-result
        without any invoke before it.
        """
        body = [
            "move-result v0",
            "return-void"
        ]
        
        # This should NOT raise UnboundLocalError
        try:
            result = self.engine.analyze_method(body)
            success = True
        except UnboundLocalError as e:
            success = False
            print(f"Bug #9 reproduced: {e}")
        
        self.assertTrue(success, "Bug #9: UnboundLocalError when move-result without invoke")

    def test_normal_invoke_flow(self):
        """
        Normal case: invoke followed by move-result should work.
        """
        body = [
            "invoke-virtual {v0}, Ljava/lang/String;->length()I",
            "move-result v1",
            "return-void"
        ]
        
        result = self.engine.analyze_method(body)
        
        # Should have tracked the source
        self.assertIsInstance(result, dict)

    def test_multiple_invoke_move_result(self):
        """
        Multiple invokes followed by move-results.
        """
        body = [
            "invoke-virtual {v0}, Ljava/lang/String;->length()I",
            "move-result v1",
            "invoke-virtual {v1}, Ljava/lang/String;->toString()Ljava/lang/String;",
            "move-result v2",
            "return-void"
        ]
        
        result = self.engine.analyze_method(body)
        self.assertIsInstance(result, dict)

    def test_invoke_without_move_result(self):
        """
        Invoke without move-result should not cause issues.
        """
        body = [
            "const/4 v0, 0x1",
            "invoke-static {v0}, Lsome/Class;->doSomething(I)V",
            "return-void"
        ]
        
        result = self.engine.analyze_method(body)
        self.assertIsInstance(result, dict)

    def test_empty_method(self):
        """
        Empty method body should not cause issues.
        """
        body = []
        
        result = self.engine.analyze_method(body)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 0)

    def test_only_const(self):
        """
        Method with only const instructions.
        """
        body = [
            "const/4 v0, 0x1",
            "return-void"
        ]
        
        result = self.engine.analyze_method(body)
        self.assertIsInstance(result, dict)

if __name__ == "__main__":
    unittest.main()

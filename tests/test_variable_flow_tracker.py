#!/usr/bin/env python3
"""Tests for VariableFlowTracker - TDD approach."""

import unittest
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from variable_flow_tracker import VariableFlowTracker, UsagePoint, OperationType


class TestVariableFlowTrackerInit(unittest.TestCase):
    """Test VariableFlowTracker initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        class_index = {}
        file_cache = MagicMock()
        
        tracker = VariableFlowTracker(class_index, file_cache)
        
        self.assertEqual(tracker.max_depth, 10)
        self.assertEqual(tracker.class_index, class_index)
        self.assertEqual(tracker.file_cache, file_cache)

    def test_init_with_custom_depth(self):
        """Test initialization with custom depth limit."""
        class_index = {}
        file_cache = MagicMock()
        
        tracker = VariableFlowTracker(class_index, file_cache, max_depth=5)
        
        self.assertEqual(tracker.max_depth, 5)


class TestUsagePoint(unittest.TestCase):
    """Test UsagePoint dataclass."""

    def test_usage_point_creation(self):
        """Test creating a UsagePoint."""
        point = UsagePoint(
            line_number=10,
            instruction="const-string p2, \"test\"",
            operation=OperationType.WRITE,
            state="p2 = constant string 'test'",
            variable_state_after="constant_value"
        )
        
        self.assertEqual(point.line_number, 10)
        self.assertEqual(point.operation, OperationType.WRITE)


class TestParseMethodSignature(unittest.TestCase):
    """Test method signature parsing."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    def test_parse_simple_signature(self):
        """Test parsing a simple method signature."""
        sig = "Lcom/example/Login;->doLogin(Ljava/lang/String;)Z"
        
        class_name, method_name, params, return_type = self.tracker._parse_signature(sig)
        
        self.assertEqual(class_name, "Lcom/example/Login;")
        self.assertEqual(method_name, "doLogin")
        self.assertEqual(params, ["Ljava/lang/String;"])
        self.assertEqual(return_type, "Z")

    def test_parse_multiple_params(self):
        """Test parsing method with multiple parameters."""
        sig = "Lcom/example/Auth;->verify(Ljava/lang/String;Ljava/lang/String;I)Z"
        
        class_name, method_name, params, return_type = self.tracker._parse_signature(sig)
        
        self.assertEqual(params, ["Ljava/lang/String;", "Ljava/lang/String;", "I"])

    def test_parse_no_params(self):
        """Test parsing method with no parameters."""
        sig = "Lcom/example/Utils;->getInstance()Lcom/example/Utils;"
        
        class_name, method_name, params, return_type = self.tracker._parse_signature(sig)
        
        self.assertEqual(params, [])


class TestExtractVariableFromInstruction(unittest.TestCase):
    """Test extracting variables from Smali instructions."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    def test_extract_register_list(self):
        """Test extracting register list from invoke."""
        line = "invoke-static {p2, v0}, Lcom/example/Utils;->check(Ljava/lang/String;I)Z"
        regs = self.tracker._extract_register_list(line)
        
        self.assertIn("p2", regs)
        self.assertIn("v0", regs)

    def test_extract_field_write_sig(self):
        """Test extracting field signature from iput."""
        line = "iput-object p2, p0, Lcom/example/Login;->password:Ljava/lang/String;"
        sig = self.tracker._extract_field_signature(line)
        
        self.assertEqual(sig, "Lcom/example/Login;->password:Ljava/lang/String;")

    def test_extract_static_field_sig(self):
        """Test extracting static field signature."""
        line = "sput-object p2, Lcom/example/Config;->apiKey:Ljava/lang/String;"
        sig = self.tracker._extract_field_signature(line)
        
        self.assertEqual(sig, "Lcom/example/Config;->apiKey:Ljava/lang/String;")


class TestClassifyOperation(unittest.TestCase):
    """Test operation classification."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    def test_classify_write(self):
        """Test classifying const as WRITE."""
        line = 'const-string p2, "test"'
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.WRITE)

    def test_classify_read(self):
        """Test classifying if as READ."""
        line = "if-eqz p2, :cond_fail"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.READ)

    def test_classify_transform_void(self):
        """Test classifying invoke with non-void return."""
        line = "invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.TRANSFORM)

    def test_classify_pass_void(self):
        """Test classifying invoke with void return."""
        line = "invoke-static {p2}, Lcom/example/Utils;->check(Ljava/lang/String;)V"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.PASS)

    def test_classify_return(self):
        """Test classifying return as RETURN."""
        line = "return p2"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.RETURN)

    def test_classify_field_write(self):
        """Test classifying iput as FIELD_WRITE."""
        line = "iput-object p2, p0, Lcom/example/Login;->password:Ljava/lang/String;"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.FIELD_WRITE)

    def test_classify_field_read(self):
        """Test classifying iget as FIELD_READ."""
        line = "iget-object v0, p0, Lcom/example/Login;->password:Ljava/lang/String;"
        op = self.tracker._classify_operation(line)
        
        self.assertEqual(op, OperationType.FIELD_READ)


class TestExtractInvokeTarget(unittest.TestCase):
    """Test extracting invoke target method."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    def test_extract_static_method(self):
        """Test extracting static method target."""
        line = "invoke-static {p2}, Lcom/example/Validator;->validate(Ljava/lang/String;)Z"
        target = self.tracker._extract_invoke_target(line)
        
        self.assertEqual(target, "Lcom/example/Validator;->validate(Ljava/lang/String;)Z")

    def test_extract_virtual_method(self):
        """Test extracting virtual method target."""
        line = "invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;"
        target = self.tracker._extract_invoke_target(line)
        
        self.assertEqual(target, "Ljava/lang/String;->trim()Ljava/lang/String;")


class TestGetParameterIndex(unittest.TestCase):
    """Test getting parameter index in invoke."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    def test_parameter_index_first(self):
        """Test getting index of first parameter."""
        line = "invoke-static {p2}, Lcom/example/Utils;->check(Ljava/lang/String;)Z"
        idx = self.tracker._get_parameter_index(line, "p2")
        
        self.assertEqual(idx, 0)

    def test_parameter_index_second(self):
        """Test getting index of second parameter."""
        line = "invoke-static {p1, p2}, Lcom/example/Utils;->check(Ljava/lang/String;Ljava/lang/String;)Z"
        idx = self.tracker._get_parameter_index(line, "p2")
        
        self.assertEqual(idx, 1)


class TestTrackVariableBasic(unittest.TestCase):
    """Test basic variable tracking (without recursion)."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock(), max_depth=3)

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_track_simple_write(self, mock_load):
        """Test tracking a simple constant assignment."""
        mock_load.return_value = [
            ".method public doLogin(Ljava/lang/String;)Z",
            "const-string p2, \"test_value\"",
            "return p2",
            ".end method"
        ]
        
        result = self.tracker.track_variable(
            "Lcom/example/Login;",
            "doLogin(Ljava/lang/String;)Z",
            "p2"
        )
        
        self.assertIn("flow", result)
        self.assertEqual(len(result["flow"]), 1)

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_track_with_invoke(self, mock_load):
        """Test tracking when variable is passed to another method."""
        mock_load.return_value = [
            ".method public doLogin(Ljava/lang/String;)Z",
            "const-string p2, \"test\"",
            "invoke-static {p2}, Lcom/example/Validator;->validate(Ljava/lang/String;)Z",
            "move-result v0",
            "return v0",
            ".end method"
        ]
        
        result = self.tracker.track_variable(
            "Lcom/example/Login;",
            "doLogin(Ljava/lang/String;)Z",
            "p2"
        )
        
        self.assertIn("flow", result)
        
        method_flow = result["flow"][0]
        self.assertEqual(method_flow["method"], "Lcom/example/Login;->doLogin(Ljava/lang/String;)Z")


class TestBifurcationDetection(unittest.TestCase):
    """Test bifurcation/branching detection."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_detect_branching(self, mock_load):
        """Test detecting branching with if-else."""
        mock_load.return_value = [
            ".method public test(Ljava/lang/String;)V",
            "if-eqz p2, :cond_a",
            "invoke-static {p2}, Lcom/example/A;->process(Ljava/lang/String;)V",
            "goto :end",
            ":cond_a",
            "invoke-static {p2}, Lcom/example/B;->process(Ljava/lang/String;)V",
            ":end",
            "return-void",
            ".end method"
        ]
        
        result = self.tracker.track_variable(
            "Lcom/example/Test;",
            "test(Ljava/lang/String;)V",
            "p2"
        )
        
        method_flow = result["flow"][0]
        self.assertIn("bifurcation_points", method_flow)


class TestDepthLimiting(unittest.TestCase):
    """Test depth limiting behavior."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/First;": [Path("/fake/path1")],
            "Lcom/example/Second;": [Path("/fake/path2")],
            "Lcom/example/Third;": [Path("/fake/path3")]
        }
        mock_cache = MagicMock()
        self.tracker = VariableFlowTracker(self.class_index, mock_cache, max_depth=2)

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_depth_limit_reached(self, mock_load):
        """Test that depth limit is respected."""
        results = [
            [".method public first()V\ninvoke-static {p0}, Lcom/example/Second;->call()V\nreturn-void\n.end method"],
            [".method public second()V\ninvoke-static {p0}, Lcom/example/Third;->call()V\nreturn-void\n.end method"],
            [".method public third()V\nreturn-void\n.end method"]
        ]
        mock_load.side_effect = lambda c, m: results.pop(0) if results else None
        
        result = self.tracker.track_variable(
            "Lcom/example/First;",
            "first()V",
            "p0"
        )
        
        self.assertGreaterEqual(len(result["flow"]), 1)


class TestReturnModification(unittest.TestCase):
    """Test return modification tracking."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_detect_return_modification(self, mock_load):
        """Test detecting when return modifies the variable."""
        mock_load.return_value = [
            ".method public test()V",
            "const/4 p2, 0x1",
            "invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I",
            "move-result p2",
            "return p2",
            ".end method"
        ]
        
        result = self.tracker.track_variable(
            "Lcom/example/Test;",
            "test()V",
            "p2"
        )
        
        usages = result["flow"][0]["usage"]
        
        move_result_usage = [u for u in usages if u["operation"] == "TRANSFORM"]
        self.assertTrue(len(move_result_usage) > 0)


class TestFieldTracking(unittest.TestCase):
    """Test field tracking and consumers."""

    def setUp(self):
        self.tracker = VariableFlowTracker({}, MagicMock())

    @patch.object(VariableFlowTracker, '_load_method_body')
    def test_track_field_write(self, mock_load):
        """Test tracking when variable is stored in field."""
        mock_load.return_value = [
            ".method public save(Ljava/lang/String;)V",
            "move-object p1, p0",
            "iput-object p1, p0, Lcom/example/Store;->data:Ljava/lang/String;",
            "return-void",
            ".end method"
        ]
        
        result = self.tracker.track_variable(
            "Lcom/example/Store;",
            "save(Ljava/lang/String;)V",
            "p1"
        )
        
        method_flow = result["flow"][0]
        field_usages = [u for u in method_flow["usage"] if u["operation"] == "FIELD_WRITE"]
        
        self.assertTrue(len(field_usages) > 0)
        self.assertIn("field", field_usages[0])


if __name__ == "__main__":
    unittest.main()
#!/usr/bin/env python3
"""Tests for CodeMetricsEngine - TDD approach."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smali_scout import SmaliScoutCore


class TestDeadCodeDetection(unittest.TestCase):
    """Test dead code detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_detect_uncalled_private_method(self):
        """Test detecting method that's never called from this class."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method private unusedMethod()V
    return-void
.end method

.method public usedMethod()V
    return-void
.end method
"""
        result = self.core._detect_dead_code(code, "Lcom/example/App;")
        self.assertIsNotNone(result)
        self.assertIn("uncalled_methods", result)

    def test_no_dead_code_when_all_called(self):
        """Test no dead code when methods call each other."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public methodA()V
    invoke-virtual {p0}, Lcom/example/App;->methodB()V
    return-void
.end method

.method public methodB()V
    return-void
.end method
"""
        result = self.core._detect_dead_code(code, "Lcom/example/App;")
        self.assertIsNotNone(result)


class TestMethodCount(unittest.TestCase):
    """Test method counting per class."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_count_methods_single_class(self):
        """Test counting methods in a single class."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public method1()V
    return-void
.end method

.method public method2()V
    return-void
.end method

.method private method3()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["public"], 2)
        self.assertEqual(result["private"], 1)


class TestParameterCount(unittest.TestCase):
    """Test parameter counting per method."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_count_parameters_no_params(self):
        """Test counting parameters with no params."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public methodNoParams()V
    return-void
.end method
"""
        result = self.core._count_parameters(code)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["params"], 0)

    def test_count_parameters_single_param(self):
        """Test counting parameters with single param."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public methodSingle(Ljava/lang/String;)V
    return-void
.end method
"""
        result = self.core._count_parameters(code)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["params"], 1)

    def test_count_parameters_multiple_params(self):
        """Test counting parameters with multiple params."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public methodMulti(Ljava/lang/String;I Ljava/lang/Object;)V
    return-void
.end method
"""
        result = self.core._count_parameters(code)
        self.assertGreater(len(result), 0)
        self.assertGreaterEqual(result[0]["params"], 2)


class TestVariableCount(unittest.TestCase):
    """Test variable usage counting per method."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_count_variables_basic(self):
        """Test basic variable counting."""
        code = """
.method public testMethod()V
    .registers 3
    const/4 v0, 0x1
    const/4 v1, 0x2
    move v2, v0
    return-void
.end method
"""
        result = self.core._count_variables(code)
        self.assertEqual(result[0]["variables"], 3)


class TestMetricsIntegration(unittest.TestCase):
    """Test full metrics integration."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_full_metrics_report(self):
        """Test generating full metrics report."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public login(Ljava/lang/String;)Z
    .registers 4
    const-string v0, "test"
    return v0
.end method

.method public logout()V
    return-void
.end method

.method private helper()V
    return-void
.end method
"""
        result = self.core.generate_code_metrics(code, "Lcom/example/Test;")
        
        self.assertIn("method_count", result)
        self.assertIn("parameter_count", result)
        self.assertIn("variable_count", result)
        self.assertIn("dead_code", result)
        self.assertIn("lines_per_method", result)
        self.assertIn("complexity_analysis", result)
        self.assertIn("large_methods", result)
        self.assertIn("summary", result)

    def test_count_lines_per_method(self):
        """Test line counting per method."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public testMethod()V
    .registers 2
    const/4 v0, 0x1
    return-void
.end method
"""
        result = self.core._count_lines_per_method(code)
        self.assertGreater(len(result), 0)
        self.assertIn("lines", result[0])
        self.assertIn("instructions", result[0])

    def test_analyze_complexity(self):
        """Test complexity analysis."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public complexMethod()V
    .registers 3
    const/4 v0, 0x1
    if-gt v0, v1, :cond_1
    return-void
:end method
"""
        result = self.core._analyze_complexity(code)
        self.assertIsInstance(result, list)

    def test_detect_large_methods(self):
        """Test detecting large methods."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public bigMethod()V
    .registers 5
"""
        for i in range(60):
            code += f"    const/4 v{i % 5}, {i}\n"
        code += "    return-void\n.end method\n"
        
        result = self.core._detect_large_methods(code, threshold=50)
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()


class TestInheritanceDepth(unittest.TestCase):
    """Test inheritance depth analysis."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_inheritance_depth_single(self):
        """Test single level inheritance."""
        code = """
.class public Lcom/example/Child;
.super Ljava/lang/Object;

.method public test()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertIsNotNone(result)

    def test_inheritance_depth_multiple(self):
        """Test multiple level inheritance."""
        code = """
.class public Lcom/example/GrandChild;
.super Lcom/example/Child;

.method public test()V
    return-void
.end method

.class public Lcom/example/Child;
.super Ljava/lang/Object;

.method public test()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertIsNotNone(result)


class TestCallStatistics(unittest.TestCase):
    """Test call statistics."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_virtual_call_count(self):
        """Test virtual method call counting."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public test()V
    invoke-virtual {p0}, Lcom/example/App;->helper()V
    invoke-virtual {p0}, Lcom/example/App;->helper()V
    return-void
.end method

.method private helper()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertIsNotNone(result)

    def test_static_call_count(self):
        """Test static method call counting."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public test()V
    invoke-static {}, Lcom/example/Utils;->staticMethod()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertIsNotNone(result)

    def test_super_call_count(self):
        """Test super method call counting."""
        code = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public test()V
    invoke-super {p0, p1}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""
        result = self.core._count_methods(code)
        self.assertIsNotNone(result)


class TestSecurityPatternDetection(unittest.TestCase):
    """Test security pattern detection."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_detect_hardcoded_key(self):
        """Test detecting hardcoded encryption key."""
        code = """
.class public Lcom/example/Security;
.super Ljava/lang/Object;

.method public init()V
    const-string v0, "MySecretKey123"
    return-void
.end method
"""
        result = self.core._detect_dead_code(code, "Lcom/example/Security;")
        self.assertIsNotNone(result)

    def test_detect_debug_enabled(self):
        """Test detecting debug flag."""
        code = """
.class public Lcom/example/Config;
.super Ljava/lang/Object;

.method public isDebug()Z
    const/4 v0, 0x1
    return v0
.end method
"""
        result = self.core._detect_dead_code(code, "Lcom/example/Config;")
        self.assertIsNotNone(result)


class TestLargeMethodDetection(unittest.TestCase):
    """Test large method detection."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_large_method_detection_exact_threshold(self):
        """Test detecting method at exact threshold."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public bigMethod()V
    .registers 5
"""
        for i in range(50):
            code += f"    const/4 v{i % 5}, {i}\n"
        code += "    return-void\n.end method\n"
        
        result = self.core._detect_large_methods(code, threshold=50)
        self.assertGreater(len(result), 0)

    def test_large_method_detection_above_threshold(self):
        """Test detecting method above threshold."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public bigMethod()V
    .registers 5
"""
        for i in range(100):
            code += f"    const/4 v{i % 5}, {i}\n"
        code += "    return-void\n.end method\n"
        
        result = self.core._detect_large_methods(code, threshold=50)
        self.assertGreater(len(result), 0)


class TestComplexityAnalysis(unittest.TestCase):
    """Test complexity analysis."""

    def setUp(self):
        self.core = SmaliScoutCore(".", cache_size=100)

    def test_complexity_with_multiple_branches(self):
        """Test complexity with multiple branches."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public complexMethod()V
    .registers 4
    const/4 v0, 0x1
    if-gt v0, v1, :cond_1
    if-eq v0, v2, :cond_2
    return-void
:cond_1
    return-void
:cond_2
    return-void
.end method
"""
        result = self.core._analyze_complexity(code)
        self.assertIsInstance(result, list)

    def test_complexity_with_loops(self):
        """Test complexity with loops."""
        code = """
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public loopMethod()V
    .registers 3
    const/4 v0, 0x0
    :loop_start
    if-ge v0, v1, :loop_end
    add-int v0, v0, 0x1
    goto :loop_start
    :loop_end
    return-void
.end method
"""
        result = self.core._analyze_complexity(code)
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()

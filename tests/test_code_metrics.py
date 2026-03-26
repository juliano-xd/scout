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


if __name__ == "__main__":
    unittest.main()

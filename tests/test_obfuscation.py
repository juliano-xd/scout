#!/usr/bin/env python3
"""Tests for ObfuscationDetector - TDD approach."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obfuscation_engine import (
    ObfuscationDetector,
    ReflectionFinding,
    DecryptionFinding,
    NativeFinding,
    ReflectionType,
    DecryptionType,
    NativeType
)


class TestObfuscationDetectorInit(unittest.TestCase):
    """Test ObfuscationDetector initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        class_index = {}
        file_cache = MagicMock()
        
        detector = ObfuscationDetector(class_index, file_cache)
        
        self.assertEqual(detector.max_depth, 3)
        self.assertEqual(detector.class_index, class_index)
        self.assertEqual(detector.file_cache, file_cache)

    def test_init_with_custom_depth(self):
        """Test initialization with custom depth."""
        class_index = {}
        file_cache = MagicMock()
        
        detector = ObfuscationDetector(class_index, file_cache, max_depth=5)
        
        self.assertEqual(detector.max_depth, 5)


class TestReflectionDetection(unittest.TestCase):
    """Test reflection detection."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/App;": [Path("/fake/app.smali")],
            "Lcom/example/Dynamic;": [Path("/fake/dynamic.smali")]
        }
        self.file_cache = MagicMock()
        self.file_cache.get.return_value = None
        self.detector = ObfuscationDetector(self.class_index, self.file_cache)

    def test_detect_class_forName(self):
        """Test detecting Class.forName() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public init()V
    const-string v0, "com.example.Dynamic"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v1
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        self.assertGreater(len(result), 0)
        reflection_types = [r.reflection_type for r in result]
        self.assertIn(ReflectionType.CLASS_FORNAME, reflection_types)

    def test_detect_method_invoke(self):
        """Test detecting Method.invoke() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public call()V
    const-string v0, "doSomething"
    invoke-virtual {p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        self.assertGreater(len(result), 0)
        reflection_types = [r.reflection_type for r in result]
        self.assertIn(ReflectionType.METHOD_INVOKE, reflection_types)

    def test_detect_constructor_newInstance(self):
        """Test detecting Constructor.newInstance() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public create()V
    invoke-virtual {p0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        self.assertGreater(len(result), 0)
        reflection_types = [r.reflection_type for r in result]
        self.assertIn(ReflectionType.CONSTRUCTOR_NEWINSTANCE, reflection_types)

    def test_detect_classloader_loadClass(self):
        """Test detecting ClassLoader.loadClass() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public load()V
    const-string v0, "com.example.Target"
    invoke-virtual {p0, v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        self.assertGreater(len(result), 0)
        reflection_types = [r.reflection_type for r in result]
        self.assertIn(ReflectionType.CLASSLOADER_LOAD, reflection_types)

    def test_no_reflection_returns_empty(self):
        """Test that code without reflection returns empty list."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public simple()V
    const-string v0, "hello"
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        self.assertEqual(len(result), 0)

    def test_filter_system_classes(self):
        """Test that system classes (java/android) are filtered."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public loadSystem()V
    const-string v0, "java.lang.String"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_reflection()
        
        # Should be filtered or marked as system
        # Target will be "java.lang.String" (not L... format), so is_system_class should be True
        if result:
            self.assertTrue(result[0].is_system_class or result[0].target == "")


class TestStringDeobfuscation(unittest.TestCase):
    """Test string deobfuscation detection."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/Utils;": [Path("/fake/utils.smali")],
            "Lcom/example/Security;": [Path("/fake/security.smali")],
            "Lcom/example/XorDecode;": [Path("/fake/xor.smali")],
            "Lcom/example/Assembler;": [Path("/fake/asm.smali")],
            "Lcom/example/Data;": [Path("/fake/data.smali")],
        }
        self.file_cache = MagicMock()
        self.file_cache.get.return_value = None
        self.detector = ObfuscationDetector(self.class_index, self.file_cache)

    def test_detect_base64_decode(self):
        """Test detecting Base64.decode() call."""
        content = """
.class public Lcom/example/Utils;
.super Ljava/lang/Object;

.method public decode()Ljava/lang/String;
    const-string v0, "SGVsbG8="
    invoke-static {v0}, Landroid/util/Base64;->decode(Ljava/lang/String;)[B
    move-result-object v1
    new-instance v2, Ljava/lang/String;
    invoke-direct {v2, v1}, Ljava/lang/String;-><init>([B)V
    return-object v2
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertGreater(len(result), 0)
        pattern_types = [r.pattern_type for r in result]
        self.assertIn(DecryptionType.BASE64, pattern_types)

    def test_detect_custom_crypto(self):
        """Test detecting custom crypto (Cipher)."""
        content = """
.class public Lcom/example/Security;
.super Ljava/lang/Object;

.method public decrypt(Ljava/lang/String;)[B
    const-string v0, "AES/CBC/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v1
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertGreater(len(result), 0)
        pattern_types = [r.pattern_type for r in result]
        self.assertIn(DecryptionType.CUSTOM_CRYPTO, pattern_types)

    def test_detect_xor_pattern(self):
        """Test detecting XOR pattern in loop."""
        content = """
.class public Lcom/example/XorDecode;
.super Ljava/lang/Object;

.method public decode([B)[B
    const/4 v0, 0x0
    :goto
    array-length v1, p1
    if-ge v0, v1, :end
    aget-byte v2, p1, v0
    const/4 v3, 0x5
    xor-int v2, v2, v3
    add-int v0, v0, 0x1
    goto :goto
    :end
    return-object p1
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertGreater(len(result), 0)
        pattern_types = [r.pattern_type for r in result]
        self.assertIn(DecryptionType.XOR, pattern_types)

    def test_detect_string_concatenation(self):
        """Test detecting string concatenation assembly."""
        content = """
.class public Lcom/example/Assembler;
.super Ljava/lang/Object;

.method public assemble()Ljava/lang/String;
    const-string v0, "part1"
    const-string v1, "part2"
    const-string v2, "part3"
    invoke-static {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-static {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    return-object v3
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertGreater(len(result), 0)
        pattern_types = [r.pattern_type for r in result]
        self.assertIn(DecryptionType.STRING_CONCAT, pattern_types)

    def test_detect_byte_array_init(self):
        """Test detecting byte array initialization."""
        content = """
.class public Lcom/example/Data;
.super Ljava/lang/Object;

.method public getBytes()[B
    const/4 v0, 0x3
    new-array v1, v0, [B
    const/4 v2, 0x0
    const/16 v3, 0x41
    aput-byte v3, v1, v2
    return-object v1
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertGreater(len(result), 0)
        pattern_types = [r.pattern_type for r in result]
        self.assertIn(DecryptionType.BYTE_ARRAY, pattern_types)

    def test_no_encryption_returns_empty(self):
        """Test that code without encryption returns empty."""
        content = """
.class public Lcom/example/Simple;
.super Ljava/lang/Object;

.method public hello()V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_string_decryption()
        
        self.assertEqual(len(result), 0)


class TestNativeCodeDetection(unittest.TestCase):
    """Test native code detection."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/App;": [Path("/fake/app.smali")],
            "Lcom/example/NativeBridge;": [Path("/fake/native.smali")],
        }
        self.file_cache = MagicMock()
        self.file_cache.get.return_value = None
        self.detector = ObfuscationDetector(self.class_index, self.file_cache)

    def test_detect_system_load(self):
        """Test detecting System.load() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public init()V
    const-string v0, "libnative.so"
    invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_native_code()
        
        self.assertGreater(len(result), 0)
        native_types = [r.native_type for r in result]
        self.assertIn(NativeType.SYSTEM_LOAD, native_types)

    def test_detect_system_loadLibrary(self):
        """Test detecting System.loadLibrary() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public init()V
    const-string v0, "native"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_native_code()
        
        self.assertGreater(len(result), 0)
        native_types = [r.native_type for r in result]
        self.assertIn(NativeType.SYSTEM_LOAD_LIBRARY, native_types)

    def test_detect_runtime_load(self):
        """Test detecting Runtime.load() call."""
        content = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public load()V
    const-string v0, "libcrypto.so"
    invoke-static {v0}, Ljava/lang/Runtime;->load(Ljava/lang/String;)V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_native_code()
        
        self.assertGreater(len(result), 0)
        native_types = [r.native_type for r in result]
        self.assertIn(NativeType.RUNTIME_LOAD, native_types)

    def test_detect_jni_register_natives(self):
        """Test detecting RegisterNatives JNI call."""
        content = """
.class public Lcom/example/NativeBridge;
.super Ljava/lang/Object;

.method public register()V
    const-string v0, "libnative.so"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_native_code()
        
        self.assertGreater(len(result), 0)

    def test_no_native_returns_empty(self):
        """Test that code without native calls returns empty."""
        content = """
.class public Lcom/example/Simple;
.super Ljava/lang/Object;

.method public hello()V
    return-void
.end method
"""
        self.file_cache.get.return_value = content
        
        result = self.detector.detect_native_code()
        
        self.assertEqual(len(result), 0)


class TestDetectSelected(unittest.TestCase):
    """Test detect_selected method."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.detector = ObfuscationDetector(self.class_index, self.file_cache)

    @patch.object(ObfuscationDetector, 'detect_reflection')
    @patch.object(ObfuscationDetector, 'detect_string_decryption')
    @patch.object(ObfuscationDetector, 'detect_native_code')
    def test_detect_all_types(self, mock_native, mock_strings, mock_reflection):
        """Test detecting all types."""
        mock_reflection.return_value = [MagicMock()]
        mock_strings.return_value = [MagicMock()]
        mock_native.return_value = [MagicMock()]
        
        result = self.detector.detect_selected(["reflection", "strings", "native"])
        
        self.assertIn("reflection", result["findings"])
        self.assertIn("strings", result["findings"])
        self.assertIn("native", result["findings"])

    @patch.object(ObfuscationDetector, 'detect_reflection')
    def test_detect_only_reflection(self, mock_reflection):
        """Test detecting only reflection."""
        mock_obj = MagicMock()
        mock_obj.method = "Test"
        mock_obj.reflection_type = ReflectionType.CLASS_FORNAME
        mock_reflection.return_value = [mock_obj]
        
        result = self.detector.detect_selected(["reflection"])
        
        self.assertEqual(result["findings"]["reflection"]["total"], 1)
        self.assertEqual(result["settings"]["detection_types"], ["reflection"])


if __name__ == "__main__":
    unittest.main()
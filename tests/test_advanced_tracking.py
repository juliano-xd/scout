#!/usr/bin/env python3
"""Tests for AdvancedTrackingEngine - TDD approach."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from advanced_tracking_engine import (
    AdvancedTrackingEngine,
    TaintSource,
    TaintSink,
    DataFlow,
    CryptoOperation,
    SensitiveType,
    SinkType
)


class TestAdvancedTrackingEngineInit(unittest.TestCase):
    """Test AdvancedTrackingEngine initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        class_index = {}
        file_cache = MagicMock()
        
        engine = AdvancedTrackingEngine(class_index, file_cache)
        
        self.assertEqual(engine.class_index, class_index)
        self.assertEqual(engine.file_cache, file_cache)
        self.assertGreater(len(engine.SENSITIVE_SOURCES), 0)
        self.assertGreater(len(engine.SINKS), 0)


class TestSourceDetection(unittest.TestCase):
    """Test sensitive source detection."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/App;": [Path("/fake/app.smali")]
        }
        self.file_cache = MagicMock()
        self.file_cache.get.return_value = None
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_telephony_manager(self):
        """Test detecting TelephonyManager.getDeviceId."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
            "Lcom/example/App;->getId()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.DEVICE_INFO)

    def test_detect_location_manager(self):
        """Test detecting LocationManager.getLastKnownLocation."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;",
            "Lcom/example/App;->getLocation()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.LOCATION)

    def test_detect_credentials_string(self):
        """Test detecting hardcoded credentials."""
        result = self.engine._detect_source(
            'const-string v0, "password123"',
            "Lcom/example/App;->check()V",
            5
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.CREDENTIAL)

    def test_detect_api_key_string(self):
        """Test detecting API key string."""
        result = self.engine._detect_source(
            'const-string v0, "api_key_xyz123"',
            "Lcom/example/App;->init()V",
            8
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.CREDENTIAL)

    def test_detect_token_string(self):
        """Test detecting auth token string."""
        result = self.engine._detect_source(
            'const-string v0, "bearer_token_abc"',
            "Lcom/example/App;->auth()V",
            12
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.CREDENTIAL)

    def test_no_source_returns_none(self):
        """Test that non-sensitive code returns None."""
        result = self.engine._detect_source(
            "const-string v0, \"hello world\"",
            "Lcom/example/App;->hello()V",
            1
        )
        
        self.assertIsNone(result)

    def test_detect_biometric_source(self):
        """Test detecting BiometricManager authentication."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/hardware/biometrics/BiometricPrompt;->authenticate(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;Landroid/os/CancellationSignal;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V",
            "Lcom/example/App;->authenticate()V",
            5
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.BIOMETRIC)

    def test_detect_camera_source(self):
        """Test detecting Camera open."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/hardware/Camera;->open(I)Landroid/hardware/Camera;",
            "Lcom/example/App;->openCamera()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.CAMERA)

    def test_detect_microphone_source(self):
        """Test detecting AudioRecord."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/media/AudioRecord;->startRecording()V",
            "Lcom/example/App;->startRecording()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.MICROPHONE)


class TestSinkDetection(unittest.TestCase):
    """Test sink detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_network_sink(self):
        """Test detecting HttpURLConnection.connect."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V",
            "Lcom/example/App;->send()V",
            20
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.NETWORK)

    def test_detect_okhttp_sink(self):
        """Test detecting OkHttpClient.newCall."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1}, Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;",
            "Lcom/example/App;->request()V",
            25
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.NETWORK)

    def test_detect_file_sink(self):
        """Test detecting FileOutputStream.write."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1}, Ljava/io/FileOutputStream;->write([B)V",
            "Lcom/example/App;->save()V",
            30
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.FILE)

    def test_detect_log_sink(self):
        """Test detecting Log.d call."""
        result = self.engine._detect_sink(
            "invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
            "Lcom/example/App;->debug()V",
            35
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.LOG)

    def test_detect_shared_prefs_sink(self):
        """Test detecting SharedPreferences.putString."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
            "Lcom/example/App;->savePrefs()V",
            40
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.SHARED_PREFS)

    def test_no_sink_returns_none(self):
        """Test that non-sink code returns None."""
        result = self.engine._detect_sink(
            "const-string v0, \"test\"",
            "Lcom/example/App;->hello()V",
            1
        )
        
        self.assertIsNone(result)

    def test_detect_intent_extra_sink(self):
        """Test detecting Intent.putExtra."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
            "Lcom/example/App;->sendIntent()V",
            45
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.INTENT)

    def test_detect_bundle_sink(self):
        """Test detecting Bundle.putString."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1, v2}, Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V",
            "Lcom/example/App;->saveBundle()V",
            50
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.BUNDLE)


class TestCryptoDetection(unittest.TestCase):
    """Test crypto operation detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_cipher_init(self):
        """Test detecting Cipher.getInstance."""
        result = self.engine._detect_crypto(
            "invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            "Lcom/example/Security;->init()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "cipher_init")

    def test_detect_secret_key_spec(self):
        """Test detecting SecretKeySpec for key generation."""
        result = self.engine._detect_crypto(
            "invoke-direct {v0, v1, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V",
            "Lcom/example/Security;->createKey()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "key_gen")

    def test_detect_message_digest(self):
        """Test detecting MessageDigest for hashing."""
        result = self.engine._detect_crypto(
            "invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;",
            "Lcom/example/Hash;->compute()V",
            20
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "hash_init")

    def test_no_crypto_returns_none(self):
        """Test that non-crypto code returns None."""
        result = self.engine._detect_crypto(
            "const-string v0, \"test\"",
            "Lcom/example/App;->hello()V",
            1
        )
        
        self.assertIsNone(result)


class TestDataFlowMatching(unittest.TestCase):
    """Test data flow matching between sources and sinks."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_match_flow_same_method(self):
        """Test matching source and sink in same method."""
        source = TaintSource(
            register="v0",
            source_type=SensitiveType.CREDENTIAL,
            value="password",
            line=5,
            method="Lcom/example/App;->login()V"
        )
        
        sink = TaintSink(
            register="v1",
            sink_type=SinkType.NETWORK,
            target="HttpURLConnection.connect",
            line=25,
            method="Lcom/example/App;->login()V"
        )
        
        flows = self.engine._match_flows([source], [sink])
        
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].risk_level, "high")

    def test_no_match_different_methods(self):
        """Test no matching when source and sink in different methods."""
        source = TaintSource(
            register="v0",
            source_type=SensitiveType.CREDENTIAL,
            value="password",
            line=5,
            method="Lcom/example/App;->getPassword()V"
        )
        
        sink = TaintSink(
            register="v1",
            sink_type=SinkType.NETWORK,
            target="HttpURLConnection.connect",
            line=25,
            method="Lcom/example/App;->sendNetwork()V"
        )
        
        flows = self.engine._match_flows([source], [sink])
        
        self.assertEqual(len(flows), 0)

    def test_multiple_flows(self):
        """Test matching multiple flows."""
        source1 = TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "Lcom/App;->method()V")
        source2 = TaintSource("v1", SensitiveType.DEVICE_INFO, "imei", 10, "Lcom/App;->method()V")
        
        sink1 = TaintSink("v2", SinkType.NETWORK, "connect", 20, "Lcom/App;->method()V")
        sink2 = TaintSink("v3", SinkType.LOG, "log", 25, "Lcom/App;->method()V")
        
        flows = self.engine._match_flows([source1, source2], [sink1, sink2])
        
        self.assertEqual(len(flows), 2)

    def test_cross_method_flow_detection(self):
        """Test detecting flow where source method passes data to sink method."""
        flows = self.engine._match_flows(
            [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "Lcom/App;->getCred()V")],
            [TaintSink("v1", SinkType.NETWORK, "connect", 20, "Lcom/App;->sendToNetwork(Ljava/lang/String;)V")]
        )
        self.assertEqual(len(flows), 0)

    def test_cross_method_same_class_flow(self):
        """Test cross-method flow within same class via method call."""
        flows = self.engine._match_flows_cross_method(
            [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "Lcom/App;->getPassword()V")],
            [TaintSink("v1", SinkType.NETWORK, "connect", 20, "Lcom/App;->sendData(Ljava/lang/String;)V")],
            {"Lcom/App;->getPassword()V": ["Lcom/App;->sendData(Ljava/lang/String;)V"]}
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].risk_level, "high")

    def test_cross_method_no_call_relation(self):
        """Test no flow when methods don't call each other."""
        flows = self.engine._match_flows_cross_method(
            [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "Lcom/App;->getPassword()V")],
            [TaintSink("v1", SinkType.NETWORK, "connect", 20, "Lcom/App;->sendData(Ljava/lang/String;)V")],
            {}
        )
        self.assertEqual(len(flows), 0)


class TestRiskAssessment(unittest.TestCase):
    """Test risk assessment functionality."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_high_risk_credential(self):
        """Test high risk with credentials."""
        sources = [
            TaintSource("v0", SensitiveType.CREDENTIAL, "password", 5, "M"),
            TaintSource("v1", SensitiveType.CREDENTIAL, "token", 10, "M")
        ]
        sinks = [TaintSink("v2", SinkType.NETWORK, "connect", 20, "M")]
        flows = [DataFlow(sources[0], sinks[0], ["M"], "high")]
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertEqual(assessment["risk_level"], "high")
        self.assertGreater(assessment["high_risk_count"], 0)

    def test_medium_risk_device_info(self):
        """Test medium risk with device info."""
        sources = [
            TaintSource("v0", SensitiveType.DEVICE_INFO, "imei", 5, "M")
        ]
        sinks = [TaintSink("v1", SinkType.LOG, "log", 20, "M")]
        flows = []
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertEqual(assessment["risk_level"], "medium")

    def test_low_risk_no_sensitive(self):
        """Test low risk with no sensitive data."""
        sources = []
        sinks = []
        flows = []
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertEqual(assessment["risk_level"], "low")

    def test_recommendations_generated(self):
        """Test that recommendations are generated."""
        sources = [
            TaintSource("v0", SensitiveType.CREDENTIAL, "password", 5, "M")
        ]
        sinks = [
            TaintSink("v1", SinkType.NETWORK, "connect", 20, "M")
        ]
        flows = [
            DataFlow(sources[0], sinks[0], ["M"], "high")
        ]
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertGreater(len(assessment["recommendations"]), 0)


class TestAnalyzeClass(unittest.TestCase):
    """Test full class analysis."""

    def setUp(self):
        self.class_index = {
            "Lcom/example/App;": [Path("/fake/app.smali")]
        }
        self.file_cache = MagicMock()
        self.file_cache.get.return_value = None
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    @patch.object(AdvancedTrackingEngine, '_read_file')
    def test_analyze_class_with_sources_and_sinks(self, mock_read):
        """Test analyzing class with sources and sinks."""
        mock_read.return_value = """
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public getId()Ljava/lang/String;
    const-string v0, "password123"
    return-object v0
.end method

.method public send()V
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V
    return-void
.end method
"""
        
        result = self.engine.analyze_class("Lcom/example/App;")
        
        self.assertIn("sources", result)
        self.assertIn("sinks", result)
        self.assertIn("summary", result)

    def test_analyze_class_not_found(self):
        """Test analyzing non-existent class."""
        result = self.engine.analyze_class("Lcom/notexist/Class;")
        
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()


class TestURLDetection(unittest.TestCase):
    """Test URL and parameter extraction detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_url_construction(self):
        """Test detecting URL with string concatenation."""
        result = self.engine._detect_source(
            'const-string v0, "https://api.example.com/data"',
            "Lcom/example/App;->buildUrl()V",
            5
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.URL)

    def test_detect_url_with_params(self):
        """Test detecting URL with query parameters."""
        result = self.engine._detect_source(
            'const-string v0, "https://api.example.com/upload?token=xyz"',
            "Lcom/example/App;->upload()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.URL)


class TestMethodChaining(unittest.TestCase):
    """Test method chaining detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_string_builder(self):
        """Test detecting StringBuilder.append chain."""
        lines = [
            "invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            "invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
        ]
        
        result = self.engine._detect_method_chain(lines, "Lcom/example/App;->concat()V")
        self.assertTrue(result)

    def test_detect_builder_pattern(self):
        """Test detecting builder pattern (e.g., OkHttp Request.Builder)."""
        result = self.engine._detect_method_chain(
            ["invoke-virtual {v0}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;"],
            "Lcom/example/App;->build()V"
        )
        self.assertTrue(result)


class TestJSONOutput(unittest.TestCase):
    """Test JSON output structure for AI consumption."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_json_has_summary_section(self):
        """Test JSON output has summary section."""
        result = self.engine._build_json_output([], [], [], {})
        self.assertIn("summary", result)

    def test_json_has_sources_section(self):
        """Test JSON output has sources section."""
        result = self.engine._build_json_output([], [], [], {})
        self.assertIn("sources", result)

    def test_json_has_sinks_section(self):
        """Test JSON output has sinks section."""
        result = self.engine._build_json_output([], [], [], {})
        self.assertIn("sinks", result)

    test_json_has_flows_section = lambda self: self.assertIn("data_flows", self.engine._build_json_output([], [], [], {}))

    def test_json_summary_contains_counts(self):
        """Test summary contains correct counts."""
        sources = [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "M")]
        sinks = [TaintSink("v1", SinkType.NETWORK, "connect", 10, "M")]
        flows = [DataFlow(sources[0], sinks[0], ["M"], "high")]
        
        result = self.engine._build_json_output(sources, sinks, flows, {})
        
        self.assertEqual(result["summary"]["total_sources"], 1)
        self.assertEqual(result["summary"]["total_sinks"], 1)
        self.assertEqual(result["summary"]["total_flows"], 1)

    def test_json_sources_formatted(self):
        """Test sources are formatted with required fields."""
        sources = [TaintSource("v0", SensitiveType.CREDENTIAL, "password123", 5, "Lcom/App;->login()V")]
        
        result = self.engine._build_json_output(sources, [], [], {})
        
        self.assertEqual(len(result["sources"]), 1)
        self.assertIn("type", result["sources"][0])
        self.assertIn("value", result["sources"][0])
        self.assertIn("method", result["sources"][0])
        self.assertIn("line", result["sources"][0])

    def test_json_sinks_formatted(self):
        """Test sinks are formatted with required fields."""
        sinks = [TaintSink("v1", SinkType.NETWORK, "connect", 10, "Lcom/App;->send()V")]
        
        result = self.engine._build_json_output([], sinks, [], {})
        
        self.assertEqual(len(result["sinks"]), 1)
        self.assertIn("type", result["sinks"][0])
        self.assertIn("target", result["sinks"][0])
        self.assertIn("method", result["sinks"][0])

    def test_json_risk_level_included(self):
        """Test risk level is included in output."""
        sources = [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "M")]
        sinks = [TaintSink("v1", SinkType.NETWORK, "connect", 10, "M")]
        flows = [DataFlow(sources[0], sinks[0], ["M"], "high")]
        
        result = self.engine._build_json_output(sources, sinks, flows, {"risk_level": "high", "high_risk_count": 1, "medium_risk_count": 0, "recommendations": []})
        
        self.assertIn("risk_level", result["summary"])
        self.assertEqual(result["summary"]["risk_level"], "high")

    def test_json_recommendations_included(self):
        """Test recommendations are included."""
        sources = [TaintSource("v0", SensitiveType.CREDENTIAL, "pass", 5, "M")]
        sinks = [TaintSink("v1", SinkType.NETWORK, "connect", 10, "M")]
        flows = [DataFlow(sources[0], sinks[0], ["M"], "high")]
        
        result = self.engine._build_json_output(sources, sinks, flows, {"recommendations": ["Test rec"]})
        
        self.assertIn("recommendations", result["summary"])


class TestMoreSinkDetection(unittest.TestCase):
    """Test additional sink detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_clipboard_sink(self):
        """Test detecting ClipboardManager."""
        result = self.engine._detect_sink(
            "invoke-virtual {p0, v0}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V",
            "Lcom/example/App;->copy()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.CLIPBOARD)

    def test_detect_sms_sink(self):
        """Test detecting SmsManager.sendTextMessage."""
        result = self.engine._detect_sink(
            "invoke-virtual {p0, v0, v1, v2}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V",
            "Lcom/example/App;->sendSms()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.SMS)

    def test_detect_database_sink(self):
        """Test detecting SQLite database write."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)I",
            "Lcom/example/App;->save()V",
            20
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.DATABASE)

    def test_detect_system_property_sink(self):
        """Test detecting SystemProperties.set."""
        result = self.engine._detect_sink(
            "invoke-static {v0, v1}, Landroid/os/SystemProperties;->set(Ljava/lang/String;Ljava/lang/String;)V",
            "Lcom/example/App;->setProp()V",
            25
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.SYSTEM)

    def test_detect_process_builder_sink(self):
        """Test detecting ProcessBuilder.start."""
        result = self.engine._detect_sink(
            "invoke-virtual {v0}, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;",
            "Lcom/example/App;->exec()V",
            30
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.sink_type, SinkType.SYSTEM)


class TestMoreSourceDetection(unittest.TestCase):
    """Test additional source detection."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_contact_source(self):
        """Test detecting ContactsContract query."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/provider/ContactsContract;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
            "Lcom/example/App;->getContacts()V",
            5
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.PII)

    def test_detect_calendar_source(self):
        """Test detecting CalendarContract query."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/provider/CalendarContract;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
            "Lcom/example/App;->getEvents()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.PII)

    def test_detect_account_source(self):
        """Test detecting AccountManager.getAccounts."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/accounts/AccountManager;->getAccounts()[Landroid/accounts/Account;",
            "Lcom/example/App;->getAccounts()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.PII)

    def test_detect_wifi_info_source(self):
        """Test detecting WifiManager."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/net/wifi/WifiInfo;->getMacAddress()Ljava/lang/String;",
            "Lcom/example/App;->getWifi()V",
            20
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.DEVICE_INFO)

    def test_detect_bluetooth_source(self):
        """Test detecting BluetoothAdapter."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->getAddress()Ljava/lang/String;",
            "Lcom/example/App;->getBt()V",
            25
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.DEVICE_INFO)

    def test_detect_fingerprint_source(self):
        """Test detecting FingerprintManager."""
        result = self.engine._detect_source(
            "invoke-virtual {p0}, Landroid/hardware/fingerprint/FingerprintManager;->authenticate(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;Landroid/os/CancellationSignal;Landroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;)V",
            "Lcom/example/App;->auth()V",
            30
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.source_type, SensitiveType.BIOMETRIC)


class TestCryptoEdgeCases(unittest.TestCase):
    """Test crypto detection edge cases."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_detect_cipher_do_final(self):
        """Test detecting Cipher.doFinal."""
        result = self.engine._detect_crypto(
            "invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B",
            "Lcom/example/Security;->decrypt()V",
            10
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "cipher_final")

    def test_detect_key_generator(self):
        """Test detecting KeyGenerator."""
        result = self.engine._detect_crypto(
            "invoke-static {v0}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            "Lcom/example/Security;->genKey()V",
            15
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "key_gen")

    def test_detect_key_store(self):
        """Test detecting KeyStore."""
        result = self.engine._detect_crypto(
            "invoke-virtual {p0}, Ljava/security/KeyStore;->getKey(Ljava/lang/String;[C)Ljava/security/Key;",
            "Lcom/example/Security;->getKey()V",
            20
        )
        
        self.assertIsNotNone(result)
        self.assertIn(result.operation_type, ["key_gen", "key_load"])

    def test_detect_mac(self):
        """Test detecting Mac for MAC generation."""
        result = self.engine._detect_crypto(
            "invoke-static {v0}, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;",
            "Lcom/example/Hash;->computeMac()V",
            25
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.operation_type, "hash_init")

    def test_detect_signature(self):
        """Test detecting Signature for signing."""
        result = self.engine._detect_crypto(
            "invoke-static {v0}, Ljava/security/Signature;->getInstance(Ljava/lang/String;)Ljava/security/Signature;",
            "Lcom/example/Security;->sign()V",
            30
        )
        
        self.assertIsNotNone(result)
        self.assertIn(result.operation_type, ["signature_init", "hash_init"])


class TestDataFlowRiskLevels(unittest.TestCase):
    """Test risk level calculation."""

    def setUp(self):
        self.class_index = {}
        self.file_cache = MagicMock()
        self.engine = AdvancedTrackingEngine(self.class_index, self.file_cache)

    def test_high_risk_with_location(self):
        """Test high risk with location to network."""
        sources = [
            TaintSource("v0", SensitiveType.LOCATION, "location", 5, "M")
        ]
        sinks = [
            TaintSink("v1", SinkType.NETWORK, "connect", 20, "M")
        ]
        flows = [DataFlow(sources[0], sinks[0], ["M"], "high")]
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertEqual(assessment["risk_level"], "high")

    def test_medium_risk_pii_to_log(self):
        """Test medium risk with PII to log."""
        sources = [
            TaintSource("v0", SensitiveType.PII, "email", 5, "M")
        ]
        sinks = [
            TaintSink("v1", SinkType.LOG, "log", 20, "M")
        ]
        flows = []
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertIn(assessment["risk_level"], ["medium", "high"])

    def test_low_risk_no_sensitive_to_file(self):
        """Test low risk with non-sensitive data to file."""
        sources = []
        sinks = [
            TaintSink("v1", SinkType.FILE, "write", 20, "M")
        ]
        flows = []
        
        assessment = self.engine._assess_risk(sources, sinks, flows)
        
        self.assertEqual(assessment["risk_level"], "low")


if __name__ == "__main__":
    unittest.main()
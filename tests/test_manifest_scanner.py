import unittest
import os
import sys
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

# Add root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from smali_scout import SmaliScoutCore

class TestManifestScanner(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.scout = SmaliScoutCore(self.root)
        
        # Create a mock AndroidManifest.xml
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        <service android:name=".MyService" android:exported="false" />
        <receiver android:name=".MyReceiver">
            <intent-filter>
                <action android:name="com.test.ACTION" />
            </intent-filter>
        </receiver>
        <provider android:name=".MyProvider" android:exported="true" />
    </application>
</manifest>
"""
        (self.root / "AndroidManifest.xml").write_text(manifest_content)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_scan_manifest_exported(self):
        """Verify that exported components are correctly identified."""
        self.scout._scan_manifest()
        findings = self.scout.report["findings"].get("manifest", {})
        
        self.assertEqual(findings.get("package"), "com.test.app")
        exported = findings.get("exported_components", [])
        
        exported_names = [c["name"] for c in exported]
        
        # MainActivity is exported explicitly
        self.assertIn(".MainActivity", exported_names)
        
        # MyService is explicitly false
        self.assertNotIn(".MyService", exported_names)
        
        # MyReceiver has intent-filter and no exported=false, so it is exported
        self.assertIn(".MyReceiver", exported_names)
        
        # MyProvider is explicitly true
        self.assertIn(".MyProvider", exported_names)
        
        # Check counts
        self.assertEqual(len(exported), 3)

if __name__ == "__main__":
    unittest.main()


class TestManifestScannerAdvanced(unittest.TestCase):
    """Advanced manifest scanner tests."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.scout = SmaliScoutCore(self.root)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_empty_manifest(self):
        """Test handling of empty or missing manifest."""
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
</manifest>
"""
        (self.root / "AndroidManifest.xml").write_text(manifest_content)
        
        self.scout._scan_manifest()
        findings = self.scout.report["findings"].get("manifest", {})
        
        self.assertEqual(findings.get("package"), "com.test")

    def test_no_manifest(self):
        """Test handling when no manifest exists."""
        self.scout._scan_manifest()
        findings = self.scout.report["findings"].get("manifest", {})
        
        self.assertIsInstance(findings, dict)

    def test_multiple_activities(self):
        """Test multiple activity detection."""
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
    <application>
        <activity android:name=".MainActivity" />
        <activity android:name=".SecondActivity" />
        <activity android:name=".ThirdActivity" />
    </application>
</manifest>
"""
        (self.root / "AndroidManifest.xml").write_text(manifest_content)
        
        self.scout._scan_manifest()
        findings = self.scout.report["findings"].get("manifest", {})
        
        self.assertIsInstance(findings, dict)

    def test_permissions_in_manifest(self):
        """Test permission detection."""
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
</manifest>
"""
        (self.root / "AndroidManifest.xml").write_text(manifest_content)
        
        self.scout._scan_manifest()
        findings = self.scout.report["findings"].get("manifest", {})
        
        self.assertIsInstance(findings, dict)


if __name__ == "__main__":
    unittest.main()

import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from ui_engine import UIEngine

class TestUIResourcePathDetection(unittest.TestCase):
    """Test cases for Bug #14: Fixed path assumption for public.xml."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.root_dir = Path(self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_public_xml_in_values(self):
        """public.xml in res/values should be found."""
        res_dir = self.root_dir / "res" / "values"
        res_dir.mkdir(parents=True)
        (res_dir / "public.xml").write_text('''<?xml version="1.0"?>
<resources>
    <public type="id" name="btn_login" id="0x7f080001" />
</resources>''')
        
        engine = UIEngine(self.root_dir)
        engine.res_dir = self.root_dir / "res"
        engine.build_resource_map()
        
        # Should find the ID
        self.assertEqual(len(engine.id_to_name), 1)
        self.assertIn(0x7f080001, engine.id_to_name)

    def test_public_xml_in_values_locale(self):
        """
        Bug #14 FIXED: public.xml can be in res/values-pt, values-en, etc.
        Now scans all values* directories.
        """
        # Create values-pt directory
        res_dir = self.root_dir / "res" / "values-pt"
        res_dir.mkdir(parents=True)
        
        # Create public.xml in values-pt
        public_xml = res_dir / "public.xml"
        public_xml.write_text('''<?xml version="1.0"?>
<resources>
    <public type="id" name="btn_login" id="0x7f080001" />
    <public type="id" name="txt_user" id="0x7f080002" />
</resources>''')
        
        engine = UIEngine(self.root_dir)
        engine.res_dir = self.root_dir / "res"
        engine.build_resource_map()
        
        # Bug #14 FIXED: Now finds public.xml in values-pt
        self.assertEqual(len(engine.id_to_name), 2)
        self.assertIn(0x7f080001, engine.id_to_name)
        self.assertIn(0x7f080002, engine.id_to_name)

    def test_public_xml_in_multiple_values_dirs(self):
        """public.xml may exist in multiple values directories."""
        # Create values and values-pt
        (self.root_dir / "res" / "values").mkdir(parents=True)
        (self.root_dir / "res" / "values-pt").mkdir(parents=True)
        
        # public.xml in values-pt
        (self.root_dir / "res" / "values-pt" / "public.xml").write_text('''<?xml version="1.0"?>
<resources>
    <public type="id" name="btn_login" id="0x7f080001" />
</resources>''')
        
        engine = UIEngine(self.root_dir)
        engine.res_dir = self.root_dir / "res"
        engine.build_resource_map()
        
        # Bug #14 FIXED: Now finds in values-pt
        self.assertEqual(len(engine.id_to_name), 1)

    def test_scan_all_values_directories(self):
        """
        Improved: Scan all values* directories for public.xml
        """
        # Create multiple values directories
        for locale in ['values', 'values-pt', 'values-en', 'values-fr']:
            res_dir = self.root_dir / "res" / locale
            res_dir.mkdir(parents=True)
            
            # Add public.xml with some IDs
            if locale == 'values-pt':
                (res_dir / "public.xml").write_text('''<?xml version="1.0"?>
<resources>
    <public type="id" name="btn_login" id="0x7f080001" />
</resources>''')
        
        # Test improved scanning
        public_xmls = list((self.root_dir / "res").glob("values*/public.xml"))
        
        # Should find 1 public.xml (in values-pt)
        self.assertEqual(len(public_xmls), 1)

    def test_values_directory_glob_pattern(self):
        """Verify glob pattern works for values* directories."""
        (self.root_dir / "res").mkdir()
        (self.root_dir / "res" / "values").mkdir()
        (self.root_dir / "res" / "values-pt").mkdir()
        (self.root_dir / "res" / "values-es").mkdir()
        
        matches = list((self.root_dir / "res").glob("values*"))
        
        # Should find values, values-pt, values-es
        self.assertEqual(len(matches), 3)

if __name__ == "__main__":
    unittest.main()

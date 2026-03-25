#!/usr/bin/env python3

import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ScoutUI")

class UIEngine:
    """
    Engine for mapping Android UI elements (IDs/Names) to Smali logic handlers.
    Bridges the gap between 'what the user sees' and 'what the code does'.
    """

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.res_dir = root_dir / "res"
        # Map: 0x7f080001 -> "btn_login"
        self.id_to_name: Dict[int, str] = {}
        # Map: "btn_login" -> 0x7f080001
        self.name_to_id: Dict[str, int] = {}
        # Map: "activity_main" -> ["btn_login", "txt_user"]
        self.layout_to_ids: Dict[str, List[str]] = {}

    def build_resource_map(self):
        """Scans res/values*/public.xml to map hex IDs to symbolic names."""
        # Bug #14 fix: Scan all values* directories (values, values-pt, values-en, etc.)
        public_xml_files = list(self.res_dir.glob("values*/public.xml"))
        
        if not public_xml_files:
            logger.warning("[UI] res/values*/public.xml not found. ID mapping will be limited.")
            return

        for public_xml in public_xml_files:
            try:
                tree = ET.parse(public_xml)
                root = tree.getroot()
                for entry in root.findall("public"):
                    # <public type="id" name="btn_login" id="0x7f080001" />
                    res_type = entry.get("type")
                    if res_type == "id":
                        name = entry.get("name")
                        raw_id = entry.get("id")
                        if name and raw_id:
                            val = int(raw_id, 16)
                            self.id_to_name[val] = name
                            self.name_to_id[name] = val
                logger.info(f"[UI] Mapped {len(self.id_to_name)} resource IDs from {public_xml}.")
            except Exception as e:
                logger.error(f"[UI] Error parsing {public_xml}: {e}")

    def scan_r_classes(self, class_index: Dict[str, List[Path]], read_callback):
        """
        Fallback: Scans R.smali classes (R$id, R$string, etc.) for resource IDs.
        Useful when public.xml is missing or incomplete.
        """
        logger.info("[UI] Attempting R.smali resource recovery...")
        r_patterns = {
            "id": re.compile(r"R\$id;"),
            "string": re.compile(r"R\$string;"),
            "layout": re.compile(r"R\$layout;"),
            "drawable": re.compile(r"R\$drawable;")
        }
        
        # Regex to find: .field public static final name:I = 0x7f010001
        field_p = re.compile(r'\.field\s+public\s+static\s+final\s+([^:]+):I\s+=\s+(0x[a-fA-F0-9]+)')
        
        recovered_count = 0
        for sig, paths in class_index.items():
            for r_type, regex in r_patterns.items():
                if regex.search(sig):
                    path = paths[0]
                    try:
                        content = read_callback(path)
                        for name, hex_val in field_p.findall(content):
                            val = int(hex_val, 16)
                            if val not in self.id_to_name:
                                self.id_to_name[val] = name
                                self.name_to_id[name] = val
                                recovered_count += 1
                    except Exception:
                        continue
        
        if recovered_count > 0:
            logger.info(f"[UI] Recovered {recovered_count} resource IDs from R.smali classes.")

    def scan_layouts(self):
        """Scans res/layout/*.xml to map layouts to the IDs they contain."""
        layout_dir = self.res_dir / "layout"
        if not layout_dir.exists():
            return

        for layout_file in layout_dir.glob("*.xml"):
            layout_name = layout_file.stem
            ids = []
            try:
                # Basic parsing to find android:id attributes
                content = layout_file.read_text(encoding="utf-8", errors="ignore")
                # regex: android:id="@id/name" or android:id="@+id/name"
                found_ids = re.findall(r'android:id="@\+?id/([^"]+)"', content)
                self.layout_to_ids[layout_name] = list(set(found_ids))
                
                # new: find onClick handlers
                found_clicks = re.findall(r'android:onClick="([^"]+)"', content)
                if found_clicks:
                    if "clicks" not in self.layout_to_ids: # Use a special key or better storage
                         self.layout_to_ids[f"{layout_name}_clicks"] = list(set(found_clicks))
            except Exception:
                pass

    def get_id_info(self, query: str) -> Optional[Tuple[int, str]]:
        """Query by hex ID (str) or by name (str)."""
        if query.startswith("0x"):
            try:
                val = int(query, 16)
                return val, self.id_to_name.get(val, "unknown")
            except ValueError:
                return None
        else:
            if query in self.name_to_id:
                return self.name_to_id[query], query
        return None

    def trace_event_flow(self, ui_query: str, core_indexer: Dict[str, List[Path]]) -> List[Dict]:
        """
        Heuristic: Trace where this UI element is handled in code.
        Returns a list of potential logic handlers (Classes/Methods).
        """
        info = self.get_id_info(ui_query)
        if not info:
            return []

        hex_id, name = info
        results = []

        # 1. Find which classes use this ID (e.g. constant loading)
        # We look for: const v0, 0x7f080001 (or decimal equivalent)
        patterns = [
            re.compile(f"const(?:-int|/high16)? [vp0-9]+, {hex(hex_id)}", re.IGNORECASE),
            re.compile(f"const(?:-int|/high16)? [vp0-9]+, {str(hex_id)}", re.IGNORECASE)
        ]

        logger.info(f"[UI] Tracing logic for {name} ({hex(hex_id)})")

        for cl, paths in core_indexer.items():
            path = paths[-1]
            try:
                # Optimize: only scan classes that are likely handlers (Activity, Fragment, Listeners)
                # But for now, scan all for maximum accuracy
                content = path.read_text(encoding="utf-8", errors="ignore")
                
                for pattern in patterns:
                    if pattern.search(content):
                        # This class references the ID. Let's find the method.
                        # Usually, it's followed by a findViewById or setOnClickListener nearby
                        results.append({
                            "class": cl,
                            "file": str(path),
                            "reason": f"References ID {name}"
                        })
                        break
            except Exception:
                continue

        return results

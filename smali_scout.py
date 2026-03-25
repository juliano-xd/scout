#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from frida_engine import FridaEngine
from cfg_engine import CFGEngine
from inheritance_engine import InheritanceEngine
from scout_knowledge import ScoutKnowledge
from ui_engine import UIEngine
from reasoning_engine import ReasoningEngine
from semantic_engine import SemanticEngine
from behavior_engine import BehaviorEngine

# JSON Schema for Scout reports (for AI validation)
SCOUT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "SmaliScout Report",
    "type": "object",
    "required": ["timestamp", "target", "stats", "findings"],
    "properties": {
        "timestamp": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp of report generation",
        },
        "target": {
            "type": "string",
            "description": "Absolute path to the analyzed project directory",
        },
        "stats": {
            "type": "object",
            "properties": {
                "classes": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total number of classes indexed",
                }
            },
        },
        "findings": {
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "object",
                    "properties": {
                        "flags": {
                            "type": "object",
                            "properties": {
                                "debuggable": {"type": "boolean"},
                                "allowBackup": {"type": "boolean"},
                            },
                        },
                        "entry_points": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                            },
                        },
                    },
                },
                "scans": {"type": "object", "additionalProperties": {"type": "array"}},
                "resource_map": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string"},
                            "file": {"type": "string"},
                        },
                    },
                },
                "resource_usage": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "class": {"type": "string"},
                                "line": {"type": "integer"},
                                "context": {"type": "string"},
                            },
                        },
                    },
                },
                "brain": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 2,
                            "maxItems": 2,
                        },
                    },
                },
                "search": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "type": {"type": "string"},
                        "total_matches": {"type": "integer", "minimum": 0},
                        "results": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string"},
                                    "class": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "context": {"type": "string"},
                                    "match": {"type": "string"},
                                    "confidence": {
                                        "type": "number",
                                        "minimum": 0,
                                        "maximum": 1,
                                    },
                                },
                                "required": ["file", "class", "line", "match"],
                            },
                        },
                        "truncated": {"type": "boolean"},
                    },
                    "required": [
                        "query",
                        "type",
                        "total_matches",
                        "results",
                        "truncated",
                    ],
                },
            },
        },
    },
}


# Structured error codes for machine parsing
class ErrorCodes:
    SUCCESS = "SUCCESS"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    CLASS_NOT_FOUND = "CLASS_NOT_FOUND"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    INVALID_SEARCH_TYPE = "INVALID_SEARCH_TYPE"
    INVALID_PATH = "INVALID_PATH"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INDEXING_FAILED = "INDEXING_FAILED"
    SCAN_FAILED = "SCAN_FAILED"
    PATCH_FAILED = "PATCH_FAILED"
    REPORT_CORRUPTED = "REPORT_CORRUPTED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


# Logging ajustado para clareza e verbosidade configurável
logger = logging.getLogger("ScoutCore")
# Configuração padrão será sobrescrita conforme argumentos


from tracking_engine import TrackingEngine
# XREFEngine body removed; delegated to tracking_engine.py


ProgressCallback = Callable[[str, int, int, Optional[str]], None]

AI_HELP_TEXT = r"""
Scout: Definitive Technical Specification & Operational Contract
===============================================================

1. SYSTEM PHILOSOPHY
====================
Scout is a headless forensic engine designed for deep static analysis of Android Smali bytecode.
It prioritizes structured interoperability, technical neutrality, and high-fidelity reconstruction
of obfuscated logic. It is built as a multi-tier framework for automated security auditing.

2. CORE ARCHITECTURE & ENGINE PROTOCOLS
=======================================

2.1. TrackingEngine (tracking_engine.py)
----------------------------------------
- XREFEngine: High-performance cross-reference indexing with pickle persistence
- TaintEngine: Register-based Data Flow Analysis (DFA)
- Propagation: Follows move-register, move-result, and instance-field instructions
- Constant Tracking: Supports string and integer via const/4, const/16, const-string
- Determination Rules (Priority):
    1. SOURCE:  Values from API return (invoke-...) + move-result
    2. FIELD:   Values read via sget/iget
    3. CONST:   Constant values loaded via const/4, const/16, const-string
    4. SINK:    Values passed as arguments to sensitive APIs
- Register Naming: SOURCE > FIELD > CONST > SINK priority

2.2. CFGEngine (cfg_engine.py)
-------------------------------
- Decomposes methods into Basic Blocks (nodes) and jumps (edges)
- Handles: if-eq/ne, goto, switch (packed/sparse)
- Exception mapping with .catch directives
- Exports to DOT format for Graphviz

2.3. SemanticEngine (semantic_engine.py)
----------------------------------------
- High-fidelity bytecode-to-pseudocode translation
- Statement folding for readability
- Try-catch reconstruction
- Taint-aware register naming integration

2.4. InheritanceEngine (inheritance_engine.py)
----------------------------------------------
- Breadth-First Search (BFS) for hierarchy resolution
- Interface-to-interface inheritance support
- Multi-level class hierarchies
- Iterative implementation to avoid StackOverflow

2.5. FridaEngine (frida_engine.py)
----------------------------------
- Generates Java hook scripts with overload support
- Argument inference via DFA
- Constructor detection ($init for <init>)
- Static method detection (first 20 lines heuristic)

2.6. UIEngine (ui_engine.py)
-----------------------------
- Resource ID mapping via public.xml
- Fallback: R.smali parsing
- Layout-to-code tracing
- Event handler discovery

2.7. BehaviorEngine (behavior_engine.py)
-----------------------------------------
- Fingerprint-based detection (DATA_EXFILTRATION, CRYPTO_SENSITIVE, etc.)
- Taint flow correlation for CONFIRMED_DATA_LEAK
- High-confidence behavioral analysis

2.8. ReasoningEngine (reasoning_engine.py)
-------------------------------------------
- Cross-engine correlation
- AI-ready markdown summary generation

3. DATA INTERCHANGE & SCHEMA (scout_report.json)
================================================

3.1. Report Structure
---------------------
{
  "timestamp": "ISO-8601",
  "target": "/path/to/project",
  "stats": { "classes": N },
  "findings": {
    "manifest": { "flags": {}, "entry_points": [] },
    "scans": { "vuln": [], "crypto": [], "strings": [], "integers": [] },
    "brain": {},
    "resource_map": {},
    "resource_usage": {},
    "xref": { "callers": [], "callees": [] },
    "taint_analysis": [],
    "behaviors": [],
    "semantic_translation": {}
  }
}

3.2. Behavioral Fingerprints
----------------------------
- DATA_EXFILTRATION: TelephonyManager.getDeviceId + HttpURLConnection
- CRYPTO_SENSITIVE: Cipher.init/doFinal, SecretKeySpec
- ANTI_ANALYSIS: isDebuggerConnected, System.exit
- LOCATION_TRACKING: LocationManager, LocationListener
- CONFIRMED_DATA_LEAK: Taint flow from sensitive source to network sink

4. ADVANCED COMMAND REFERENCE
=============================

[--manifest / --patch-manifest]
- Deep XML audit and mutation
- Exported: true OR (no explicit false AND has intent-filter)

[--search-type]
- regex:  Global line-based regex
- method: Matches .method definition headers
- invoke: Matches invoke- instructions
- field:  Matches .field or field-access (sget/sput/iget/iput)
- label:  Matches smali branch labels

[--translate]
- Combines CFG + Taint analysis
- Outputs Python-like pseudocode
- Includes try-catch structures

[--xref-direction / --xref-depth]
- callers: Who references this (backward)
- callees: What this references (forward)
- depth: Recursion level (default 1, max 3 recommended)

[--ui-trace]
- Resolves res/layout XML to Smali handlers
- Dual-mode: public.xml primary, R.smali fallback

5. AGENT MODUS OPERANDI
========================

Forensic Phase:
1. scout --manifest: Map entry points
2. scout --scan all: Find vulnerabilities
3. scout --brain <Class>: Profile API usage

Investigation Phase:
4. scout --xref <Method>: Call chain analysis
5. scout --translate <Method>: Read pseudocode
6. scout --cfg <Method>: Visualize control flow

Patching Phase:
7. scout --frida <Method>: Dynamic instrumentation
8. scout --hook <Method>: Static evidence collection

6. SAFETY & RELIABILITY CONTRACT
================================
- Atomic file operations (shadow-write protocol)
- Mandatory backups (.bak_timestamp)
- Smali descriptors required (not Java dot-notation)
- Max 8 worker threads

7. KNOWN LIMITATIONS
====================
- Regex-based (not full AST parser)
- 16KB header limit for class parsing
- Static-only analysis
- Multidex first-match may differ from runtime
""".strip()

def build_introspection():
    return {
        "tool": "Scout",
        "category": "android_smali_static_analysis_and_instrumentation",
        "execution_model": {
            "target_directory": "current working directory",
            "indexes_before_actions": True,
            "mutates_files_when_hooking": True,
            "default_report_file": "scout_report.json",
            "default_frida_file": "scout_hook.js",
        },
        "input_formats": {
            "class_signature": {
                "format": "Lpackage/name/ClassName;",
                "examples": ["Lcom/example/MainActivity;", "Ljava/lang/String;"],
            },
            "method_signature": {
                "format": "Lpackage/name/ClassName;->methodName(args)returnType",
                "examples": [
                    "Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V",
                    "Ljava/lang/String;->length()I",
                    "Lcom/example/Net;->send([BLjava/lang/String;)Z",
                ],
            },
        },
        "capabilities": [
            "multi_dex_class_indexing",
            "manifest_reconnaissance",
            "static_scanning",
            "class_api_behavior_profiling",
            "atomic_method_patching",
            "frida_hook_generation",
            "json_report_export",
            "recursive_xref",
            "hook_class_generation",
            "manifest_patching",
            "custom_scanner_rules",
            "graph_export",
        ],
        "engines": {
            "TrackingEngine": {
                "file": "tracking_engine.py",
                "components": ["XREFEngine", "TaintEngine"],
                "functions": ["class_indexing", "dataflow_analysis", "taint_propagation"]
            },
            "CFGEngine": {
                "file": "cfg_engine.py",
                "components": ["BasicBlock"],
                "functions": ["cfg_construction", "dot_export"]
            },
            "SemanticEngine": {
                "file": "semantic_engine.py",
                "functions": ["pseudocode_translation", "statement_folding"]
            },
            "InheritanceEngine": {
                "file": "inheritance_engine.py",
                "functions": ["hierarchy_resolution", "interface_tracking", "type_identification"]
            },
            "FridaEngine": {
                "file": "frida_engine.py",
                "functions": ["hook_generation", "argument_inference"]
            },
            "UIEngine": {
                "file": "ui_engine.py",
                "functions": ["resource_mapping", "event_tracing"]
            },
            "BehaviorEngine": {
                "file": "behavior_engine.py",
                "functions": ["fingerprint_detection", "taint_correlation"]
            },
            "ReasoningEngine": {
                "file": "reasoning_engine.py",
                "functions": ["insight_synthesis", "ai_summary"]
            },
            "ScoutKnowledge": {
                "file": "scout_knowledge.py",
                "functions": ["framework_database", "dfa_hints"]
            }
        },
        "commands": {
            "--manifest": {
                "requires": [],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.manifest"],
                "description": "Analyze AndroidManifest.xml and extract flags plus exported components.",
            },
            "--scan": {
                "requires": ["mode"],
                "accepted_values": ["vuln", "crypto", "strings", "integers", "all"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.scans"],
                "description": "Run static regex-based scanners for vulnerability and/or crypto indicators.",
            },
            "--brain": {
                "requires": ["class_signature"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.brain"],
                "description": "Profile selected API calls inside a class and return the top matches.",
            },
            "--hook": {
                "requires": ["method_signature"],
                "mutates_files": True,
                "produces_backup": True,
                "produces_report": True,
                "outputs": ["patched_smali_file", "backup_file"],
                "description": "Inject invoke-static hook call near the start of a target method.",
            },
            "--frida": {
                "requires": ["method_signature"],
                "mutates_files": False,
                "writes_file": "scout_hook.js",
                "produces_report": True,
                "description": "Generate a Frida Java hook script for a target method.",
            },
            "--translate": {
                "requires": ["method_signature"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.semantic_translation"],
                "description": "Translate Smali method to Python-like pseudocode with DFA.",
            },
            "--cfg": {
                "requires": ["method_signature"],
                "mutates_files": False,
                "writes_file": "cfg_*.dot",
                "description": "Generate DOT control flow graph for method.",
            },
            "--xref": {
                "requires": ["target"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.xref"],
                "description": "Cross-reference analysis (callers/callees).",
            },
            "--ui-trace": {
                "requires": ["id_or_name"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.ui_trace"],
                "description": "Trace UI element to code handler.",
            },
            "--reason": {
                "requires": [],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.security_insights"],
                "description": "Generate AI reasoning summary.",
            },
            "--resource-map": {
                "requires": [],
                "mutates_files": False,
                "produces_report": False,
                "description": "Display resource ID to name mappings.",
            },
            "--find-resource": {
                "requires": ["resource_id"],
                "mutates_files": False,
                "produces_report": False,
                "description": "Find where specific resource ID is used.",
            },
            "--search": {
                "requires": ["query"],
                "mutates_files": False,
                "produces_report": True,
                "outputs": ["findings.search"],
                "description": "Generic regex search in Smali code.",
            },
            "--export": {
                "requires": [],
                "mutates_files": False,
                "writes_file": "scout_report.json",
                "description": "Force report export.",
            },
            "--ai-help": {
                "requires": [],
                "mutates_files": False,
                "description": "Print full AI-oriented operational contract.",
            },
            "--introspect-json": {
                "requires": [],
                "mutates_files": False,
                "description": "Print machine-readable tool metadata in JSON.",
            },
            "--generate-hook-class": {
                "requires": [],
                "mutates_files": True,
                "writes_file": "smali/com/bx/hook/ScoutHook.smali",
                "description": "Generate the hook class smali file for instrumentation.",
            },
            "--patch-manifest": {
                "requires": ["key=value"],
                "mutates_files": True,
                "produces_backup": True,
                "description": "Modify AndroidManifest.xml flags (e.g., debuggable=true).",
            },
            "--scan-rules": {
                "requires": ["rules.json"],
                "mutates_files": False,
                "produces_report": True,
                "description": "Run custom scan rules from a JSON file.",
            },
            "--graph": {
                "requires": ["output_file"],
                "mutates_files": False,
                "writes_file": "output_file.dot",
                "description": "Generate a Graphviz DOT file of class dependencies.",
            },
        },
        "scanner_modules": {
            "vuln": ["files", "webview"],
            "crypto": ["crypto"],
            "strings": ["strings"],
            "integers": ["integers"],
            "all": ["files", "webview", "crypto", "strings", "integers"],
        },
        "artifacts": {
            "report": "scout_report.json",
            "frida_script": "scout_hook.js",
            "patch_backup": "*.bak_*",
            "patch_temp": "*.tmp_*",
            "hook_class": "smali/com/bx/hook/ScoutHook.smali",
            "manifest_backup": "AndroidManifest.xml.bak",
            "graph_file": "*.dot",
        },
        "known_limitations": [
            "regex_based_analysis",
            "no_full_smali_ast",
            "no_dynamic_analysis",
            "patch_injection_is_heuristic",
            "class_resolution_can_be_ambiguous_in_duplicate_multi_dex_cases",
            "16kb_header_limit_for_class_parsing",
            "static_method_detection_heuristic_limited"
        ],
        "behavioral_fingerprints": {
            "DATA_EXFILTRATION": ["TelephonyManager;->getDeviceId", "HttpURLConnection;->connect"],
            "CRYPTO_SENSITIVE": ["Cipher;->init", "SecretKeySpec;-><init>"],
            "ANTI_ANALYSIS": ["Debug;->isDebuggerConnected", "System;->exit"],
            "LOCATION_TRACKING": ["LocationManager;->getLastKnownLocation"],
            "CONFIRMED_DATA_LEAK": ["Taint flow: sensitive source -> network sink"]
        },
        "recommended_ai_workflow": [
            "--manifest",
            "--scan all",
            "--brain <CLASS>",
            "--xref <METHOD>",
            "--translate <METHOD>",
            "--frida <METHOD_SIGNATURE>",
            "--hook <METHOD_SIGNATURE>"
        ],
    }


class LRUCache:
    def __init__(self, capacity=1000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self._lock = threading.RLock()

    def get(self, key):
        with self._lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]

    def put(self, key, value):
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def invalidate(self, key):
        with self._lock:
            self.cache.pop(key, None)


class ProgressReporter:
    def __init__(self, callback: Optional[ProgressCallback] = None):
        self.callback = callback
        self.current = 0
        self.total = 0
        self.event_type = ""

    def start(self, event_type: str, total: int, message: Optional[str] = None):
        self.event_type = event_type
        self.total = total
        self.current = 0
        if self.callback:
            self.callback(event_type, 0, total, message)

    def update(self, increment: int = 1, message: Optional[str] = None):
        self.current += increment
        if self.callback:
            self.callback(self.event_type, self.current, self.total, message)

    def done(self, message: Optional[str] = None):
        if self.callback:
            self.callback(
                self.event_type,
                self.total,
                self.total,
                message or f"Completed {self.event_type}",
            )


class SearchEngine:
    PATTERNS = {
        "method": re.compile(r"\.method\s+.*?(\S+)\s*\(.*?\)(\S+)"),
        "class": re.compile(r"\.class\s+.*?(L[^;]+;)"),
        "const_string": re.compile(
            r'const-string(?:/jumbo)?\s+[^,]+,\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
        ),
        "const_number": re.compile(
            r"\b(?:const(?:-high|-wide|-wide/16|-wide/32)?\s+(?:\d+|0x[0-9a-fA-F]+))\b"
        ),
        "invoke": re.compile(r"invoke-\w+\s+{[^}]*},\s*(L[^;]+;->[^\s]+)"),
        "field": re.compile(
            r"(?:iget|iput|sget|sput|iget-wide|iput-wide|sget-wide|sput-wide)\s+[^,]+,\s*(L[^;]+;->[^\s]+)"
        ),
        "label": re.compile(r"^\s*(\S+):\s*$", re.MULTILINE),
    }

    def __init__(
        self,
        class_index: Dict[str, List[Path]],
        file_cache: LRUCache,
        max_workers: int = 4,
    ):
        self.class_index = class_index
        self.file_cache = file_cache
        self.max_workers = max_workers

    def search(
        self,
        query: str,
        search_type: str = "regex",
        include_dirs: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
        case_sensitive: bool = False,
        max_results: int = 1000,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> Dict[str, Any]:
        if search_type == "regex":
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(query, flags)
        elif search_type in self.PATTERNS:
            pattern = self.PATTERNS[search_type]
            if query:
                query_lower = query.lower() if not case_sensitive else query
        else:
            type_mapping = {
                "string": "const_string",
                "number": "const_number",
            }
            internal_type = type_mapping.get(search_type, search_type)
            if internal_type not in self.PATTERNS:
                raise ValueError(f"Unknown search type: {search_type}")
            pattern = self.PATTERNS[internal_type]

        files_to_search = []
        for cl, paths in self.class_index.items():
            path = paths[-1]
            if include_dirs:
                if not any(dir_name in str(path) for dir_name in include_dirs):
                    continue
            if exclude_dirs:
                if any(dir_name in str(path) for dir_name in exclude_dirs):
                    continue
            files_to_search.append((cl, path))

        total_files = len(files_to_search)
        progress = ProgressReporter(progress_callback)
        progress.start("searching", total_files, f"Searching {total_files} files")

        results = []
        total_matches = 0
        completed_files = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(
                    self._search_file,
                    cl,
                    path,
                    pattern,
                    search_type,
                    query,
                    case_sensitive,
                ): (cl, path)
                for cl, path in files_to_search
            }

            for future in as_completed(future_to_path):
                cl, path = future_to_path[future]
                try:
                    file_results = future.result()
                    if file_results:
                        results.extend(file_results)
                        total_matches += len(file_results)
                        if len(results) >= max_results:
                            for f in future_to_path:
                                f.cancel()
                            break
                except Exception as e:
                    logger = logging.getLogger("ScoutCore")
                    logger.warning(f"[SEARCH] Error searching {cl}: {e}")
                finally:
                    completed_files += 1
                    if completed_files % 10 == 0:
                        progress.update(
                            10, f"Processed {completed_files}/{total_files} files"
                        )

        progress.done(f"Found {total_matches} matches in {completed_files} files")
        results.sort(key=lambda x: (x["file"], x["line"]))

        return {
            "query": query,
            "type": search_type,
            "total_matches": total_matches,
            "results": results[:max_results],
            "truncated": len(results) > max_results,
        }

    def _search_file(
        self,
        class_name: str,
        path: Path,
        pattern: re.Pattern,
        search_type: str,
        query: str,
        case_sensitive: bool,
    ) -> List[Dict[str, Any]]:
        content = self.file_cache.get(path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except Exception:
                return []

        lines = content.splitlines()
        matches = []

        for line_num, line in enumerate(lines, 1):
            if pattern.search(line):
                if query and search_type != "regex":
                    query_lower = query.lower() if not case_sensitive else query
                    line_lower = line.lower() if not case_sensitive else line
                    if query_lower not in line_lower:
                        continue

                start_ctx = max(0, line_num - 3)
                end_ctx = min(len(lines), line_num + 2)
                context = "\n".join(lines[start_ctx:end_ctx])

                match_text = line.strip()

                matches.append(
                    {
                        "file": str(path),
                        "class": class_name,
                        "line": line_num,
                        "context": context,
                        "match": match_text,
                    }
                )

                if len(matches) >= 100:
                    break

        return matches


class SmaliScanner:
    RULES = {
        "files": re.compile(r"openFileOutput"),
        "webview": re.compile(r"setJavaScriptEnabled"),
        "crypto": re.compile(r"Cipher|MessageDigest|SecretKeySpec"),
        "strings": re.compile(
            r'const-string(?:/jumbo)?\s+[^,]+,\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
        ),
        "integers": re.compile(r"\b(?:0x[0-9a-fA-F]+|\d+)\b"),
    }

    def __init__(
        self,
        class_index: Dict[str, List[Path]],
        file_cache: LRUCache,
        max_workers: int = 4,
        progress_callback: Optional[ProgressCallback] = None,
    ):
        self.class_index = class_index
        self.file_cache = file_cache
        self.max_workers = max_workers
        self.progress_callback = progress_callback

    @staticmethod
    def extract_hex_value(val: str) -> str:
        """Normaliza valores hexadecimais para comparação (ex: 7f080001 -> 0x7f080001)."""
        if not val:
            return ""
        val = val.lower().strip()
        if val.startswith("0x"):
            return val
        if val.startswith("@"):
            return "0x" + val[1:]
        
        # Handle negative numbers
        is_negative = val.startswith("-")
        if is_negative:
            val = val[1:]

        try:
            # Check if it's a decimal number that should be hex
            if val.isdigit():
                h = hex(int(val))
                return f"-{h}" if is_negative else h
        except: pass
        
        res = "0x" + val if not val.startswith("0x") else val
        return f"-{res}" if is_negative else res

    def scan(self, scope: List[str]) -> Dict:
        active_rules = {k: v for k, v in self.RULES.items() if k in scope}

        class_path_pairs = []
        for cl, paths in self.class_index.items():
            class_path_pairs.append((cl, paths[-1]))

        results = defaultdict(set)
        string_matches = defaultdict(list)
        integer_matches = defaultdict(list)

        total_files = len(class_path_pairs)
        progress = ProgressReporter(self.progress_callback)
        progress.start("scanning", total_files, f"Scanning {total_files} classes")
        completed_files = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_class = {
                executor.submit(self._scan_single_class, cl, path, active_rules): cl
                for cl, path in class_path_pairs
            }

            for future in as_completed(future_to_class):
                cl = future_to_class[future]
                try:
                    hits, rule_data = future.result()

                    for hit in hits:
                        results[hit].add(cl)

                    if "strings" in scope and "strings" in rule_data:
                        string_matches[cl].extend(rule_data["strings"])
                    if "integers" in scope and "integers" in rule_data:
                        integer_matches[cl].extend(rule_data["integers"])
                except Exception as e:
                    logger.error(f"[SCANNER] Error scanning {cl}: {e}")
                finally:
                    completed_files += 1
                    if completed_files % 100 == 0:
                        progress.update(
                            100, f"Processed {completed_files}/{total_files} classes"
                        )

        progress.done(
            f"Scan complete: found {sum(len(v) for v in results.values())} hits"
        )

        report_data = {}
        for k, v in results.items():
            report_data[k] = list(v)

        if "strings" in scope and string_matches:
            report_data["strings_data"] = {
                cl: list(set(strings)) for cl, strings in string_matches.items()
            }

        if "integers" in scope and integer_matches:
            report_data["integers_data"] = {
                cl: list(set(ints)) for cl, ints in integer_matches.items()
            }

        return report_data

    def _scan_single_class(
        self, class_name: str, path: Path, active_rules: Dict[str, re.Pattern]
    ) -> Tuple[Set[str], Dict[str, List[str]]]:
        content = self.file_cache.get(path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except Exception:
                return set(), {}

        hits = set()
        rule_data = {}

        for rule_name, pattern in active_rules.items():
            if rule_name in ("strings", "integers"):
                matches = pattern.findall(content)
                if matches:
                    rule_data[rule_name] = matches
                    hits.add(rule_name)
            elif pattern.search(content):
                hits.add(rule_name)

        return hits, rule_data


class SmaliScoutCore:
    def __init__(
        self,
        root_dir,
        cache_size=5000,
        scanner_threads=4,
        progress_callback: Optional[ProgressCallback] = None,
        verbose: bool = False,
    ):
        self.root_dir = Path(root_dir).resolve()
        self.smali_dirs = self._get_numeric_smali_dirs()
        self.manifest_path = self._find_manifest()

        self.report = {
            "timestamp": datetime.now().isoformat(),
            "target": str(self.root_dir),
            "stats": {"classes": 0},
            "findings": {},
        }

        self.class_index = defaultdict(list)
        self.file_cache = LRUCache(capacity=cache_size)
        self.scanner_threads = scanner_threads
        self.progress_reporter = ProgressReporter(progress_callback)
        self.kb = ScoutKnowledge() # Central Knowledge Base
        self.tracking_engine = TrackingEngine(self.class_index, self.file_cache, self.kb)
        self.inheritance_engine = InheritanceEngine(self.class_index, self.read, self.kb)
        self.frida_engine = FridaEngine(self.inheritance_engine)
        self.ui_engine = UIEngine(self.root_dir)
        self.reasoning_engine = ReasoningEngine()
        self.semantic_engine = SemanticEngine()
        self.behavior_engine = BehaviorEngine()
        self.cfg_engine = CFGEngine()
        self.verbose = verbose
        self._build_index()
        self.ui_engine.build_resource_map()
        # Fallback if public.xml analysis failed or was empty
        if not self.ui_engine.id_to_name:
            self.ui_engine.scan_r_classes(self.class_index, self.read)
        self.ui_engine.scan_layouts()

    def _get_numeric_smali_dirs(self):
        dirs = [
            d.name
            for d in self.root_dir.iterdir()
            if d.is_dir() and d.name.startswith("smali")
        ]

        def _nk(n):
            if n == "smali":
                return 0
            m = re.search(r"smali_classes(\d+)", n)
            return int(m.group(1)) if m else 0

        return sorted(dirs, key=_nk)

    def _find_manifest(self):
        for p in self.root_dir.rglob("AndroidManifest.xml"):
            return p
        return None

    def _build_index(self):
        logger.info(f"[INDEXER] Scanning: {self.root_dir.name}")
        header_p = re.compile(
            r"^\.class\s+.*?(L[^;]+;).*?^\.super\s+(L[^;]+;)", re.MULTILINE | re.DOTALL
        )
        implements_p = re.compile(r"^\.implements\s+(L[^;]+;)", re.MULTILINE)

        def _task(f):
            try:
                # Otimização: ler apenas os primeiros 16KB (onde residem .class, .super, .implements)
                with open(f, "rb") as fp:
                    header = fp.read(16384)
                    if b".class" in header:
                        content = header.decode("utf-8", errors="ignore")
                        match = header_p.search(content)
                        if match:
                            cls_sig = match.group(1)
                            sup_sig = match.group(2)
                            interfaces = implements_p.findall(content)
                            return cls_sig, f, sup_sig, interfaces
            except Exception:
                pass
            return None

        files = []
        for d in self.smali_dirs:
            files.extend(list((self.root_dir / d).rglob("*.smali")))

        total_files = len(files)
        self.progress_reporter.start(
            "indexing", total_files, f"Indexing {total_files} files"
        )

        processed = 0
        with ThreadPoolExecutor() as ex:
            for res in ex.map(_task, files):
                if res:
                    cls_sig, f_path, sup_sig, interfaces = res
                    self.class_index[cls_sig].append(f_path)
                    self.inheritance_engine.add_direct_inheritance(cls_sig, sup_sig)
                    for interface in interfaces:
                        self.inheritance_engine.add_interface(cls_sig, interface)
                    self.report["stats"]["classes"] += 1
                processed += 1
                if processed % 100 == 0:
                    self.progress_reporter.update(100)

        self.progress_reporter.done(
            f"Indexed {self.report['stats']['classes']} classes"
        )

    def resolve(self, query: str) -> Optional[Path]:
        """Resolves a class signature to its file path (First-Match for Multidex)."""
        paths = self.class_index.get(query, [])
        if not paths: return None
        if len(paths) > 1:
            logger.warning(f"[MULTIDEX] Class collision for {query}. Using first match: {paths[0]}")
        return paths[0]

    def read(self, path: Path) -> str:
        """Reads a file with LRU caching and error handling."""
        c = self.file_cache.get(path)
        if c is None:
            try:
                c = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, c)
            except Exception as e:
                logger.error(f"[IO] Failed to read {path}: {e}")
                return ""
        return c

    def recon_manifest(self):
        if not self.manifest_path:
            return

        try:
            root = ET.parse(self.manifest_path).getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            logger.info(f"[MANIFEST] Recon: {self.manifest_path.name}")
            app = root.find(".//application", namespaces=ns)
            flags = {}

            if app is not None:
                flags = {
                    "debuggable": app.get(f"{{{ns['android']}}}debuggable") == "true",
                    "allowBackup": app.get(f"{{{ns['android']}}}allowBackup")
                    != "false",
                }

            eps = []
            for tag in ["activity", "service", "receiver", "provider"]:
                for comp in root.iter(tag):
                    raw_exp = comp.get(f"{{{ns['android']}}}exported")
                    has_filter = comp.find("intent-filter") is not None
                    exported = (raw_exp == "true") or (raw_exp is None and has_filter)

                    if exported:
                        eps.append(
                            {
                                "type": tag.upper(),
                                "name": comp.get(f"{{{ns['android']}}}name"),
                            }
                        )

            logger.info(f" -> Exported: {len(eps)}")
            self.report["findings"]["manifest"] = {"flags": flags, "entry_points": eps}
        except Exception as e:
            logger.error(f"[ERROR] Manifest: {e}")

    def patch_manifest(self, changes: Dict[str, str]):
        """
        Modifica AndroidManifest.xml com as alterações fornecidas.
        changes: dicionário com chave = atributo (ex: 'debuggable') e valor = 'true'/'false' ou outro.
        """
        if not self.manifest_path:
            logger.error("[ERROR] AndroidManifest.xml not found.")
            return

        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            # Buscar nó <application>
            app = root.find(".//application", namespaces=ns)
            if app is None:
                logger.error("[ERROR] No <application> tag found in manifest.")
                return

            backup_path = self.manifest_path.with_suffix(".xml.bak")
            if not backup_path.exists():
                import shutil

                shutil.copy(self.manifest_path, backup_path)
                logger.info(f"[MANIFEST] Backup saved to {backup_path}")

            for key, value in changes.items():
                attr = f"{{{ns['android']}}}{key}"
                app.set(attr, value)
                logger.info(f"[MANIFEST] Set {key}={value}")

            tree.write(self.manifest_path, encoding="utf-8", xml_declaration=True)
            logger.info("[MANIFEST] Patched successfully.")
        except Exception as e:
            logger.error(f"[MANIFEST] Patch failed: {e}")

    def patch_method(self, sig):
        if "->" not in sig:
            return logger.error(
                "[ERROR] Invalid method signature. Expected: Lpkg/Class;->method(args)return"
            )

        cl, met = sig.split("->", 1)
        path = self.resolve(cl)

        if not path:
            return logger.error(f"[ERROR] Unresolved: {cl}")

        logger.info(f"[PATCH] Target: {sig}")

        hook_cl = "Lcom/bx/hook/ScoutHook;"
        hook_m = f"on_{re.sub(r'[^a-zA-Z0-9]', '_', met.split('(')[0])}"
        lines = self.read(path).splitlines()

        if any(f"{hook_cl}->{hook_m}" in l for l in lines):
            return logger.info(" -> Already patched. Skipping.")

        new_lines = []
        applied, in_m = False, False
        injection_done = False

        # Robust regex for finding exactly the method header
        met_esc = re.escape(met)
        re_head = re.compile(fr"^\.method\s+.*?\b{met_esc}\b")

        for l in lines:
            new_lines.append(l)

            if not in_m:
                if l.startswith(".method") and re_head.search(l):
                    in_m = True

            if in_m and not applied:
                s = l.strip()

                # Tentar injetar após .locals, .registers, .prologue, .line ou antes do primeiro código
                if any(
                    s.startswith(x)
                    for x in [".locals", ".registers", ".prologue", ".line"]
                ):
                    new_lines.extend(
                        [f"    invoke-static {{}}, {hook_cl}->{hook_m}()V"]
                    )
                    applied, in_m = True, False
                    injection_done = True
                elif not injection_done and (
                    s.startswith("invoke")
                    or s.startswith("return")
                    or s.startswith("const")
                    or s.startswith("move")
                ):
                    # Se não encontrou ponto de injeção antes da primeira instrução, insere antes
                    # Remove a linha adicionada anteriormente (a última linha é a instrução)
                    new_lines.pop()
                    new_lines.extend(
                        [f"    invoke-static {{}}, {hook_cl}->{hook_m}()V", l]
                    )
                    applied, in_m = True, False
                    injection_done = True

        if applied:
            ts = datetime.now().microsecond
            tmp = path.with_suffix(f".tmp_{ts}")
            bak = path.parent / (path.name + f".bak_{datetime.now().strftime('%H%M%S')}")

            try:
                tmp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                os.rename(path, bak)
                os.rename(tmp, path)
                self.file_cache.invalidate(path)
                logger.info(f" -> SUCCESS: {path.name}")
            except Exception as e:
                logger.error(f"[ERROR] Atomic write: {e}")
        else:
            logger.error("[ERROR] Injection point not found.")

    def gen_frida(self, sig):
        body = self._get_method_body(sig)
        return self.frida_engine.write_hook(sig, method_body=body)

    def _get_method_body(self, sig: str) -> Optional[List[str]]:
        """Extrai as linhas do corpo de um método Smali."""
        if "->" not in sig:
            return None
        cl, met = sig.split("->", 1)
        path = self.resolve(cl)
        if not path:
            return None

        # Robust regex for finding exactly the method header
        met_esc = re.escape(met)
        re_head = re.compile(fr"^\.method\s+.*?\b{met_esc}\b")

        lines = self.read(path).splitlines()
        body = []
        in_m = False
        for l in lines:
            if not in_m:
                if l.startswith(".method") and re_head.search(l):
                    in_m = True
            if in_m:
                body.append(l)
                if l.strip() == ".end method":
                    break
        return body if body else None


    def gen_cfg(self, sig: str, output_path: Optional[str] = None):
        """Gera um grafo de fluxo de controle (CFG) para o método."""
        body = self._get_method_body(sig)
        if not body:
            return logger.error(f"[ERROR] Method body not found for CFG: {sig}")

        blocks = self.cfg_engine.build_cfg(body)
        dot = self.cfg_engine.to_dot(blocks, sig)

        out_file = output_path or f"cfg_{sig.replace('->', '_').replace('/', '_').replace(';', '')}.dot".replace('"', '')
        Path(out_file).write_text(dot, encoding="utf-8")
        logger.info(f"[CFG] Graph saved to {out_file}")

    def trace_ui(self, query: str):
        """Traces the logic handler for a UI element (Button/View)."""
        logger.info(f"[UI-TRACE] Query: {query}")
        handlers = self.ui_engine.trace_event_flow(query, self.class_index)
        
        if not handlers:
            logger.warning(f"[UI-TRACE] No results for {query}")
            return
            
        self.report["findings"]["ui_trace"] = {
            "query": query,
            "handlers": handlers
        }
        
        for h in handlers:
            logger.info(f" -> Potential Handler: {h['class']} ({h['reason']})")
            # Propor analisar o onClick do handler se ele for um listener
            if "OnClickListener" in h["class"] or "Activity" in h["class"]:
                logger.info(f"    [*] Tip: Inspect {h['class']}->onClick(Landroid/view/View;)V")

    def generate_report_insights(self):
        """Synthesizes gathered findings into a technical summary."""
        summary = self.reasoning_engine.generate_ai_summary(self.report) # Logic remains, naming changes
        print("\n" + "="*40)
        print(summary)
        print("="*40 + "\n")
        self.report["findings"]["security_insights"] = summary

    def translate_semantic(self, sig: str):
        """Translates a Smali method into high-level pseudocode with DFA-aware naming."""
        body = self._get_method_body(sig)
        if not body:
            return logger.error(f"[ERROR] Method body not found for translation: {sig}")

        # Run DFA for variable naming (TrackingEngine)
        dfa_results = self.tracking_engine.taint.analyze_method(body)

        # Convert Set to List for type compatibility
        dfa_list_results = {k: list(v) for k, v in dfa_results.items()} if dfa_results else None

        translation = self.semantic_engine.translate_method(body, dfa_list_results, self.inheritance_engine)
        print(f"\n# Semantic Translation (DFA Optimized) for {sig}:\n")
        print(translation)
        print("\n" + "="*20 + "\n")
        
        self.report["findings"]["semantic_translation"] = {
            "signature": sig,
            "pseudocode": translation
        }
        
        # Opcional: tentar gerar PNG se dot estiver disponível
        # os.system(f"dot -Tpng {out_file} -o {out_file}.png")

    def scan_unified(self, scope):
        logger.info(f"[SCAN] Scope: {scope}")

        scanner = SmaliScanner(
            class_index=self.class_index,
            file_cache=self.file_cache,
            max_workers=self.scanner_threads,
            progress_callback=self.progress_reporter.callback,
        )

        results = scanner.scan(scope)
        self.report["findings"]["scans"] = results
        
        # Step 1: Automated Taint Flow Detection (V26)
        taint_flows = self._perform_taint_analysis()
        
        # Step 2: Intelligent Behavior Profiling (now with flows)
        api_counts = {}
        for rule, hits in results.items():
            if rule in ["crypto", "webview", "files", "apis"]:
                for sig, locs in hits.items(): api_counts[sig] = len(locs)
        
        self.report["findings"]["api_stats"] = api_counts
        self.report["findings"]["behaviors"] = self.behavior_engine.analyze(api_counts, taint_flows)
        self.report["findings"]["ai_reasoning"] = self.reasoning_engine.generate_ai_summary(self.report)

        # New: Manifest Scan
        self._scan_manifest()


        hits_summary = {}
        for key, value in results.items():
            # Handle list vs dict in results
            if isinstance(value, dict):
                 if key in ("strings_data", "integers_data"):
                     hits_summary[key] = sum(len(items) for items in value.values())
                 else:
                     hits_summary[key] = len(value)
            else:
                 hits_summary[key] = len(value)

        total_hits = sum(hits_summary.values())
        logger.info(f" -> Found: {total_hits} hits ({hits_summary})")

        # Automatically build resource map if integers were scanned
        if "integers" in scope and "integers_data" in results:
            self._map_resource_ids(results["integers_data"])
            # Agora também analisa os usos
            self._find_resource_usages(results["integers_data"])

    def _perform_taint_analysis(self) -> List[Dict]:
        """Orchestrates automated taint profiling for all identified sensitive APIs."""
        logger.info("[TAINT] Starting automated data flow analysis...")
        scans = self.report["findings"].get("scans", {})
        
        api_findings = {}
        for cat in ["crypto", "webview", "apis"]:
            if cat in scans: api_findings.update(scans[cat])
                
        if not api_findings:
            logger.info("[TAINT] No sensitive APIs found for taint analysis.")
            return []

        taint_results = self.tracking_engine.perform_full_taint_scan(self, api_findings)
        self.report["findings"]["taint_analysis"] = taint_results
        logger.info(f" -> [TAINT] Analysis complete: identified {len(taint_results)} data-flow paths.")
        return taint_results

    def ensure_xref_built(self):
        """Ensures XREF indexes are built using the consolidated engine."""
        self.tracking_engine.xref.build_indexes()
        # Note: self.report["findings"]["xref"] can be updated if needed, but build_indexes now handles persistence

    def _map_resource_ids(self, integers_data: Dict[str, List[str]]):
        logger.info("[RESOURCE MAP] Building resource ID map...")
        resource_map = {}

        # Procurar em res/values* (qualquer pasta que comece com values)
        res_values_dirs = list(self.root_dir.glob("res/values*"))
        if not res_values_dirs:
            logger.warning("[RESOURCE MAP] No res/values* directories found")
            self.report["findings"]["resource_map"] = {}
            return

        xml_files = []
        for vals_dir in res_values_dirs:
            xml_files.extend(vals_dir.glob("*.xml"))

        logger.info(f"[RESOURCE MAP] Scanning {len(xml_files)} XML files")

        for xml_file in xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()

                for public in root.findall("public"):
                    if public.get("type") == "id":
                        name = public.get("name")
                        res_id = public.get("id")
                        if name and res_id:
                            normalized_id = SmaliScanner.extract_hex_value(res_id)
                            resource_map[normalized_id] = {
                                "name": name,
                                "type": "id",
                                "file": xml_file.name,
                            }
                # Também pode extrair de <string>, <dimen>, etc. se necessário
            except Exception as e:
                logger.warning(f"[RESOURCE MAP] Error parsing {xml_file}: {e}")
                continue

        self.resource_map = resource_map
        self.report["findings"]["resource_map"] = resource_map

        mapped_count = 0
        for class_name, int_list in integers_data.items():
            for int_val in int_list:
                normalized = SmaliScanner.extract_hex_value(int_val)
                if normalized in resource_map:
                    mapped_count += 1

        logger.info(f"[RESOURCE MAP] Mapped {mapped_count} resource IDs to definitions")
        logger.info(
            f"[RESOURCE MAP] Total unique resource definitions found: {len(resource_map)}"
        )

    def _find_resource_usages(
        self, integers_data: Dict[str, List[str]]
    ) -> Dict[str, List[Dict]]:
        logger.info("[RESOURCE USAGE] Analyzing resource ID usage locations...")
        usage_map = defaultdict(list)

        for class_name, int_list in integers_data.items():
            path = self.resolve(class_name)
            if not path:
                continue

            try:
                content = self.read(path)
                lines = content.splitlines()

                for line_num, line in enumerate(lines, 1):
                    for int_val in int_list:
                        normalized = SmaliScanner.extract_hex_value(int_val)
                        if normalized in self.resource_map:
                            # Melhorar busca: usar regex que captura o ID como palavra inteira ou precedido por não-alfanumérico
                            # Match both 0x123 and 123 formats
                            pattern = rf"(?<![0-9a-fA-Fx])(?:0x)?{re.escape(int_val.replace('0x', ''))}(?![0-9a-fA-Fx])"
                            if re.search(pattern, line, re.IGNORECASE):
                                usage_map[normalized].append(
                                    {
                                        "class": class_name,
                                        "line": line_num,
                                        "context": line.strip(),
                                    }
                                )
            except Exception as e:
                logger.warning(f"[RESOURCE USAGE] Error reading {class_name}: {e}")
                continue

        self.report["findings"]["resource_usage"] = dict(usage_map)
        total_usages = sum(len(v) for v in usage_map.values())
        logger.info(
            f"[RESOURCE USAGE] Found {total_usages} usage locations for {len(usage_map)} resource IDs"
        )
        if self.progress_reporter.callback:
            self.progress_reporter.callback(
                "resource_usage_complete", 1, 1, f"Found {total_usages} usages"
            )
        return dict(usage_map)

    def _scan_manifest(self):
        """Parses AndroidManifest.xml to identify exported components and entry points."""
        manifest_path = self.root_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            logger.warning("[MANIFEST] AndroidManifest.xml not found.")
            return

        logger.info("[MANIFEST] Scanning for forensic markers...")
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}
            
            # 1. Exported Components
            exported_components = []
            for tag in ["activity", "service", "receiver", "provider"]:
                for component in root.findall(f".//{tag}"):
                    name = component.get(f"{{{ns['android']}}}name")
                    exported = component.get(f"{{{ns['android']}}}exported")
                    has_filter = component.find("intent-filter") is not None
                    
                    if exported == "true" or (exported is None and has_filter):
                        exported_components.append({
                            "type": tag,
                            "name": name,
                            "intent_filters": len(component.findall("intent-filter"))
                        })

            # 2. Risky Permissions
            risky_perms = [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.ACCESS_FINE_LOCATION"
            ]
            found_risky_perms = []
            for perm in root.findall(".//uses-permission"):
                p_name = perm.get(f"{{{ns['android']}}}name")
                if p_name in risky_perms:
                    found_risky_perms.append(p_name)

            # 3. Persistence Intents
            persistence_actions = [
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.QUICKBOOT_POWERON",
                "android.intent.action.PACKAGE_ADDED",
                "android.intent.action.PACKAGE_REPLACED"
            ]
            found_persistence = []
            for receiver in root.findall(".//receiver"):
                r_name = receiver.get(f"{{{ns['android']}}}name")
                for action in receiver.findall(".//action"):
                    a_name = action.get(f"{{{ns['android']}}}name")
                    if a_name in persistence_actions:
                        found_persistence.append({"receiver": r_name, "action": a_name})
            
            self.report["findings"]["manifest"] = {
                "package": root.get("package"),
                "exported_components": exported_components,
                "risky_permissions": found_risky_perms,
                "persistence_markers": found_persistence
            }
            
            if found_risky_perms:
                logger.info(f" -> Found {len(found_risky_perms)} risky permissions.")
            if found_persistence:
                logger.warning(f" -> Found {len(found_persistence)} persistence markers (BOOT/PACKAGE_ADDED).")
            logger.info(f" -> Identified {len(exported_components)} exported components.")
        except Exception as e:
            logger.error(f"[MANIFEST] Failed to parse manifest: {e}")

    def brain(self, query):
        path = self.resolve(query)
        if not path:
            return logger.error(f"[ERROR] Unresolved: {query}")

        content = self.read(path)
        api_p = re.compile(
            r"invoke-.* ([L](?:android|java|javax|okhttp|com/google|com/facebook)[^;]+;->[a-zA-Z0-9<>\$-]+)"
        )
        top = Counter(api_p.findall(content)).most_common(5)

        logger.info(f"[BRAIN] {query}")
        for a, c in top:
            logger.info(f" - {a} ({c}x)")

        self.report["findings"]["brain"] = {query: top}
        if self.progress_reporter.callback:
            self.progress_reporter.callback(
                "analysis_complete", 1, 1, f"Brain analysis for {query} complete"
            )

    def xref(
        self,
        target: str,
        direction: str = "both",
        max_depth: int = 1,
        include_system: bool = False,
    ) -> Dict:
        self.ensure_xref_built()
        
        # TrackingEngine delegation
        if "->" in target:
            callers = self.tracking_engine.xref.get_polymorphic_xrefs(target, self.inheritance_engine)
            callees = self.tracking_engine.xref.method_callees.get(target, set())
            graph = self.tracking_engine.xref.get_call_graph(target, depth=max_depth)
        else:
            # Class-level XREF
            callers = self.tracking_engine.xref.method_callers.get(target, set()) # Simplified for class
            callees = self.tracking_engine.xref.method_callees.get(target, set())
            graph = {}

        results = {
            "target": target,
            "callers": sorted(list(callers)),
            "callees": sorted(list(callees)),
            "call_graph": graph
        }

        if not include_system:
            prefix = ("Ljava/", "Landroid/", "Ljavax/", "Lcom/google/")
            results["callers"] = [r for r in results["callers"] if not r.startswith(prefix)]
            results["callees"] = [r for r in results["callees"] if not r.startswith(prefix)]

        return results

    def generate_hook_class(self):
        """
        Gera o arquivo smali para a classe de hook ScoutHook.
        """
        hook_smali_dir = self.root_dir / "smali" / "com" / "bx" / "hook"
        hook_smali_dir.mkdir(parents=True, exist_ok=True)
        hook_smali = hook_smali_dir / "ScoutHook.smali"

        if hook_smali.exists():
            logger.info("[HOOK] ScoutHook.smali already exists. Skipping.")
            return

        content = """.class public Lcom/bx/hook/ScoutHook;
.super Ljava/lang/Object;
.source "ScoutHook.java"

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static on_(Ljava/lang/String;)V
    .registers 2
    const-string v0, "ScoutHook"
    const-string v1, "Hook called: "
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
"""
        hook_smali.write_text(content, encoding="utf-8")
        logger.info(f"[HOOK] ScoutHook.smali generated at {hook_smali}")

    def scan_custom_rules(self, rules_file: Path):
        """
        Executa regras personalizadas definidas em um arquivo JSON.
        Formato: [{"name": "rule_name", "pattern": "regex"}]
        """
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception as e:
            logger.error(f"[CUSTOM SCAN] Failed to load rules: {e}")
            return

        compiled_rules = []
        for rule in rules:
            name = rule.get("name")
            pattern = rule.get("pattern")
            if name and pattern:
                try:
                    compiled_rules.append((name, re.compile(pattern)))
                except re.error as e:
                    logger.warning(
                        f"[CUSTOM SCAN] Invalid regex for rule '{name}': {e}"
                    )

        if not compiled_rules:
            logger.warning("[CUSTOM SCAN] No valid rules found.")
            return

        logger.info(f"[CUSTOM SCAN] Loaded {len(compiled_rules)} rules")
        results = defaultdict(list)

        class_path_pairs = [(cl, paths[-1]) for cl, paths in self.class_index.items()]
        total = len(class_path_pairs)
        progress = ProgressReporter(self.progress_reporter.callback)
        progress.start(
            "custom_scan", total, f"Scanning {total} classes with custom rules"
        )

        processed = 0
        with ThreadPoolExecutor(max_workers=self.scanner_threads) as executor:
            future_to_class = {
                executor.submit(
                    self._scan_single_class_custom, cl, path, compiled_rules
                ): cl
                for cl, path in class_path_pairs
            }
            for future in as_completed(future_to_class):
                cl = future_to_class[future]
                try:
                    class_results = future.result()
                    if class_results:
                        for rule_name, matches in class_results.items():
                            results[rule_name].extend(matches)
                except Exception as e:
                    logger.warning(f"[CUSTOM SCAN] Error scanning {cl}: {e}")
                finally:
                    processed += 1
                    if processed % 100 == 0:
                        progress.update(100, f"Processed {processed}/{total}")

        progress.done(
            f"Custom scan complete: {sum(len(v) for v in results.values())} hits"
        )
        self.report["findings"]["custom_scans"] = {k: v for k, v in results.items()}

    def _scan_single_class_custom(
        self, class_name: str, path: Path, rules: List[Tuple[str, re.Pattern]]
    ) -> Dict[str, List[Dict]]:
        content = self.file_cache.get(path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except Exception:
                return {}
        results = defaultdict(list)
        lines = content.splitlines()
        for rule_name, pattern in rules:
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    results[rule_name].append(
                        {
                            "class": class_name,
                            "file": str(path),
                            "line": line_num,
                            "match": line.strip(),
                        }
                    )
        return results

    def export_graph(self, output_file: str):
        """
        Gera um arquivo DOT com as dependências entre classes.
        """
        self.ensure_xref_built()
        dot_lines = ["digraph G {"]
        dot_lines.append("    rankdir=LR;")
        dot_lines.append("    node [shape=box];")

        # Adicionar nós (classes)
        all_classes = set(self.class_index.keys())
        for cls in all_classes:
            dot_lines.append(f'    "{cls}" [label="{cls}"];')

        # Adicionar arestas (chamadas)
        edges = set()
        for caller, callees in self.tracking_engine.xref.method_callees.items():
            for callee in callees:
                if callee.startswith("L") and "->" in callee:
                    callee_class = callee.split("->")[0]
                    edges.add((caller, callee_class))
        for caller, callee in edges:
            dot_lines.append(f'    "{caller}" -> "{callee}";')

        dot_lines.append("}")
        output_path = Path(output_file)
        output_path.write_text("\n".join(dot_lines), encoding="utf-8")
        logger.info(f"[GRAPH] DOT file written to {output_path}")

    def save_report(self):
        Path("scout_report.json").write_text(
            json.dumps(self.report, indent=4, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("[REPORT] Saved to scout_report.json")
        if self.progress_reporter.callback:
            self.progress_reporter.callback("report_saved", 1, 1, "Report saved")

    def search(
        self,
        query: str,
        search_type: str = "regex",
        include_dirs: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
        max_results: int = 1000,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> Dict[str, Any]:
        scanner = SearchEngine(
            class_index=self.class_index,
            file_cache=self.file_cache,
            max_workers=self.scanner_threads,
        )

        results = scanner.search(
            query=query,
            search_type=search_type,
            include_dirs=include_dirs,
            exclude_dirs=exclude_dirs,
            max_results=max_results,
        )

        return results

    def display_resource_map(self):
        if "resource_map" not in self.report.get("findings", {}):
            logger.error(
                "[RESOURCE MAP] No resource mapping available. Run --scan integers first."
            )
            return

        resource_map = self.report["findings"]["resource_map"]
        if not resource_map:
            logger.info("[RESOURCE MAP] No resource definitions found in XML files.")
            return

        logger.info(
            f"[RESOURCE MAP] Found {len(resource_map)} resource ID definitions:"
        )
        if self.progress_reporter.callback:
            self.progress_reporter.callback(
                "resource_map_display",
                1,
                1,
                f"Showing {len(resource_map)} resource definitions",
            )
        for res_id, info in sorted(resource_map.items()):
            logger.info(
                f"  {res_id} -> {info['type']}/{info['name']} (in {info['file']})"
            )

    def find_resource_usage(self, resource_id: str):
        normalized_id = SmaliScanner.extract_hex_value(resource_id)

        if "resource_map" not in self.report.get("findings", {}):
            report_path = self.root_dir / "scout_report.json"
            if report_path.exists():
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        saved_report = json.load(f)
                    if (
                        "findings" in saved_report
                        and "resource_map" in saved_report["findings"]
                    ):
                        self.report["findings"]["resource_map"] = saved_report[
                            "findings"
                        ]["resource_map"]
                        logger.info(
                            "[RESOURCE USAGE] Loaded resource map from scout_report.json"
                        )
                    else:
                        logger.error(
                            "[RESOURCE USAGE] No resource mapping available. Run --scan integers first."
                        )
                        return
                except Exception as e:
                    logger.error(f"[RESOURCE USAGE] Failed to load report: {e}")
                    return
            else:
                logger.error(
                    "[RESOURCE USAGE] No resource mapping available. Run --scan integers first."
                )
                return

        resource_map = self.report["findings"]["resource_map"]

        if normalized_id not in resource_map:
            logger.warning(
                f"[RESOURCE USAGE] Resource ID {normalized_id} not found in resource map."
            )
            # Ainda tentamos encontrar usos

        if "resource_usage" in self.report.get("findings", {}):
            usage_map = self.report["findings"]["resource_usage"]
            if normalized_id in usage_map:
                locations = usage_map[normalized_id]
                resource_info = resource_map.get(normalized_id, {})

                logger.info(
                    f"[RESOURCE USAGE] Found {len(locations)} usages of {normalized_id}"
                )
                if resource_info:
                    logger.info(
                        f"  Definition: {resource_info.get('type')}/{resource_info.get('name')} (in {resource_info.get('file')})"
                    )

                for loc in locations:
                    logger.info(
                        f"  {loc['class']} (line {loc['line']}): {loc['context']}"
                    )
                return

        logger.info(
            f"[RESOURCE USAGE] Scanning for {normalized_id} (this may take a moment)..."
        )

        usage_locations = []
        for class_name, paths in self.class_index.items():
            path = paths[-1]
            try:
                content = self.read(path)
                lines = content.splitlines()

                for line_num, line in enumerate(lines, 1):
                    if re.search(
                        rf"(?<![0-9a-fA-Fx]){re.escape(normalized_id)}(?![0-9a-fA-Fx])",
                        line,
                    ):
                        usage_locations.append(
                            {
                                "class": class_name,
                                "line": line_num,
                                "context": line.strip(),
                            }
                        )
            except Exception:
                continue

        if usage_locations:
            logger.info(
                f"[RESOURCE USAGE] Found {len(usage_locations)} usages of {normalized_id}"
            )
            for loc in usage_locations:
                logger.info(f"  {loc['class']} (line {loc['line']}): {loc['context']}")
        else:
            logger.info(f"[RESOURCE USAGE] No usages found for {normalized_id}")


def build_parser():
    description = """Scout
Ferramenta para análise estática, recon, patching e instrumentação de projetos Android em smali."""

    epilog = """Exemplos rápidos:
  Recon geral:
    scout --manifest --scan all

  Investigar uma classe:
    scout --brain Lcom/example/AuthManager;

  Gerar hook Frida:
    scout --frida 'Lcom/example/Net;->send([BLjava/lang/String;)Z'

  Aplicar patch estático:
    scout --hook 'Lcom/example/LoginActivity;->doLogin(Ljava/lang/String;Ljava/lang/String;)V'

  Buscar IDs de recursos e suas definições:
    scout --scan integers

Ajuda expandida para IA:
  scout --ai-help

Introspecção em JSON:
  scout --introspect-json"""

    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Analisa o AndroidManifest.xml e extrai flags do app e componentes exportados.",
    )
    parser.add_argument(
        "--scan",
        choices=["vuln", "crypto", "strings", "integers", "all"],
        help="Executa scanners estáticos",
    )
    parser.add_argument(
        "--resource-map",
        action="store_true",
        help="Mostra o mapeamento de resource IDs encontrados para suas definições em XML (requer --scan integers prévio).",
    )
    parser.add_argument(
        "--find-resource",
        metavar="RESOURCE_ID",
        help="Encontra onde um resource ID específico é usado no código (ex: 0x7f0b0000). Requer --scan integers prévio.",
    )
    parser.add_argument(
        "--search",
        metavar="QUERY",
        help="Busca genérica no código Smali. Pode buscar métodos, classes, strings, números, etc.",
    )
    parser.add_argument(
        "--machine-json",
        action="store_true",
        help="Output only JSON (no logs) for machine parsing.",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "text", "yaml"],
        default="json",
        help="Output format for results (default: json).",
    )
    parser.add_argument(
        "--path",
        metavar="DIRECTORY",
        help="Path to the decompiled APK directory. Defaults to current working directory.",
    )
    parser.add_argument(
        "--progress",
        choices=["none", "basic", "detailed"],
        default="basic",
        help="Progress reporting: 'none', 'basic', 'detailed'.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes (for --hook).",
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="Execute multiple commands from a file (one command per line).",
    )
    parser.add_argument(
        "--search-type",
        choices=[
            "regex",
            "method",
            "class",
            "string",
            "number",
            "const_number",
            "invoke",
            "field",
            "label",
        ],
        default="regex",
        help="Tipo de busca para --search (padrão: regex).",
    )
    parser.add_argument(
        "--search-in",
        metavar="DIRS",
        help="Diretórios específicos para buscar (ex: smali,smali_classes2). Padrão: todos.",
    )
    parser.add_argument(
        "--search-exclude",
        metavar="DIRS",
        help="Diretórios para excluir da busca (ex: smali_classes3).",
    )
    parser.add_argument(
        "--search-max",
        type=int,
        default=1000,
        help="Número máximo de resultados (padrão: 1000).",
    )
    parser.add_argument(
        "--brain",
        metavar="CLASS",
        help="Analisa uma classe smali e lista as APIs mais frequentes encontradas nela.",
    )
    parser.add_argument(
        "--xref",
        metavar="TARGET",
        help="Cross-reference analysis: find who calls a method/class or what it calls.",
    )
    parser.add_argument(
        "--xref-direction",
        choices=["callers", "callees", "both"],
        default="both",
        help="Direction for --xref.",
    )
    parser.add_argument(
        "--xref-depth",
        type=int,
        default=1,
        help="Maximum depth for recursive XREF traversal (default: 1).",
    )
    parser.add_argument(
        "--xref-include-system",
        action="store_true",
        help="Include Android system classes in XREF results.",
    )
    parser.add_argument(
        "--hook",
        metavar="METHOD_SIGNATURE",
        help="Aplica patch em um método smali, injetando invoke-static no início do método.",
    )
    parser.add_argument(
        "--frida",
        metavar="METHOD_SIGNATURE",
        help="Gera um script Frida para um método específico.",
    )
    parser.add_argument(
        "--cfg",
        metavar="METHOD_SIGNATURE",
        help="Gera um grafo de fluxo de controle (DOT) para o método especificado.",
    )
    parser.add_argument(
        "--ui-trace",
        metavar="ID_OR_NAME",
        help="Rastreia qual classe Smali lida com o elemento de UI (ex: btn_login).",
    )
    parser.add_argument(
        "--reason", action="store_true", help="Faz uma síntese lógica das descobertas."
    )
    parser.add_argument(
        "--translate",
        metavar="METHOD_SIGNATURE",
        help="Traduz um método Smali para pseudocódigo (Python-like).",
    )
    parser.add_argument(
        "--export", action="store_true", help="Força a exportação do scout_report.json."
    )
    parser.add_argument(
        "--introspect-json",
        action="store_true",
        help="Imprime em JSON todas as capacidades, formatos e contratos da ferramenta e encerra.",
    )
    parser.add_argument(
        "--generate-hook-class",
        action="store_true",
        help="Gera a classe smali ScoutHook para instrumentação.",
    )
    parser.add_argument(
        "--patch-manifest",
        metavar="KEY=VALUE",
        nargs="+",
        help="Modifica AndroidManifest.xml, ex: --patch-manifest debuggable=true allowBackup=false",
    )
    parser.add_argument(
        "--scan-rules",
        metavar="RULES_JSON",
        help="Executa regras de scanner personalizadas definidas em um arquivo JSON.",
    )
    parser.add_argument(
        "--graph",
        metavar="OUTPUT_FILE",
        help="Gera um arquivo DOT com o grafo de dependências entre classes.",
    )
    parser.add_argument(
        "--ai-help",
        action="store_true",
        help="Mostra a documentação expandida orientada para IA e encerra.",
    )
    parser.add_argument("--verbose", action="store_true", help="Ativa logs detalhados.")

    return parser


def _display_search_results(results: Dict, output_format: str = "json"):
    if output_format == "json":
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif output_format == "yaml":
        try:
            import yaml

            print(yaml.dump(results, default_flow_style=False))
        except ImportError:
            logger.error(
                "[ERROR] PyYAML not installed. Use 'pip install pyyaml' for YAML output."
            )
            print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(f"\nSearch Results: {results['query']} (type: {results['type']})")
        print(f"Total matches: {results['total_matches']}")
        if results["truncated"]:
            print(f"⚠ Results truncated (use --search-max to increase)")
        print()
        for r in results["results"]:
            print(f"{r['file']}:{r['line']}")
            print(f"  Class: {r['class']}")
            print(f"  Match: {r['match']}")
            if r.get("confidence"):
                print(f"  Confidence: {r['confidence']:.2%}")
            print(f"  Context:")
            for line in r["context"].split("\n"):
                print(f"    {line}")
            print()


def _display_xref_results(results: Dict, output_format: str = "json"):
    if output_format == "json":
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif output_format == "yaml":
        try:
            import yaml

            print(yaml.dump(results, default_flow_style=False))
        except ImportError:
            logger.error(
                "[ERROR] PyYAML not installed. Use 'pip install pyyaml' for YAML output."
            )
            print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(f"\nXREF Results for: {results['target']}")
        print(f"Direction: {results['direction']}")
        print()

        if results.get("callers"):
            print(f"Callers ({len(results['callers'])} classes that call this):")
            for caller in sorted(results["callers"])[:50]:
                print(f"  - {caller}")
            if len(results["callers"]) > 50:
                print(f"  ... and {len(results['callers']) - 50} more")
            print()

        if results.get("callees"):
            print(f"Callees ({len(results['callees'])} methods called):")
            for callee in sorted(results["callees"])[:50]:
                print(f"  - {callee}")
            if len(results["callees"]) > 50:
                print(f"  ... and {len(results['callees']) - 50} more")
            print()

        if results.get("class_references"):
            print(
                f"Class References ({len(results['class_references'])} classes referencing this):"
            )
            for ref in sorted(results["class_references"])[:50]:
                print(f"  - {ref}")
            if len(results["class_references"]) > 50:
                print(f"  ... and {len(results['class_references']) - 50} more")
            print()


def _execute_batch(batch_file: str, base_dir: str):
    import shlex
    import subprocess

    batch_path = Path(batch_file)
    if not batch_path.exists():
        logger.error(f"[ERROR] Batch file not found: {batch_file}")
        return

    logger.info(f"[BATCH] Executing commands from {batch_file}")
    commands = batch_path.read_text(encoding="utf-8").strip().split("\n")

    for i, cmd_line in enumerate(commands, 1):
        cmd_line = cmd_line.strip()
        if not cmd_line or cmd_line.startswith("#"):
            continue

        logger.info(f"[BATCH] [{i}/{len(commands)}] Executing: {cmd_line}")
        try:
            args = shlex.split(cmd_line)
            if "{BASE}" in args:
                args = [base_dir if arg == "{BASE}" else arg for arg in args]

            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve())] + args,
                cwd=base_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logger.error(
                    f"[BATCH] Command failed with exit code {result.returncode}"
                )
                logger.error(f"  stderr: {result.stderr}")
            else:
                logger.info(f"[BATCH] Command completed successfully")

        except Exception as e:
            logger.error(f"[BATCH] Error executing command: {e}")


def _preview_hook(method_sig: str, core: SmaliScoutCore):
    if "->" not in method_sig:
        logger.error(f"[ERROR] Invalid method signature: {method_sig}")
        return

    cl, met = method_sig.split("->", 1)
    path = core.resolve(cl)

    if not path:
        logger.error(f"[ERROR] Class not found: {cl}")
        return

    logger.info(f"[DRY-RUN] Would patch: {method_sig}")
    logger.info(f"  Target file: {path}")
    logger.info(f"  Hook method: Lcom/bx/hook/ScoutHook;->on_{met.split('(')[0]}()V")
    logger.info(
        f"  Backup would be created: {path}.bak_{datetime.now().strftime('%H%M%S')}"
    )
    logger.info(f"  [DRY-RUN] No changes made (remove --dry-run to apply)")


def _handle_error(
    error_code: str, message: str, is_machine_json: bool = False, **context
):
    error_obj = {
        "error": {
            "code": error_code,
            "message": message,
            "context": context,
        }
    }
    if is_machine_json:
        print(json.dumps(error_obj, ensure_ascii=False))
    else:
        logger.error(f"[{error_code}] {message}")
        if context:
            for k, v in context.items():
                logger.error(f"  {k}: {v}")
    sys.exit(1)


def _validate_signature(sig: str) -> bool:
    pattern = r"^L[^;]+;->[^\(]+\([^\)]*\)[^\s]*$"
    return bool(re.match(pattern, sig))


def _validate_path(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.is_dir()


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Configurar logging conforme verbose
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    # Substituir logger global
    global logger
    logger = logging.getLogger("ScoutCore")

    if args.ai_help:
        print(AI_HELP_TEXT)
        sys.exit(0)

    if args.introspect_json:
        print(json.dumps(build_introspection(), indent=2, ensure_ascii=False))
        sys.exit(0)

    if args.batch:
        _execute_batch(args.batch, os.getcwd())
        sys.exit(0)

    target_dir = args.path if args.path else os.getcwd()
    if not _validate_path(target_dir):
        _handle_error(
            ErrorCodes.INVALID_PATH,
            f"Target directory does not exist or is not accessible: {target_dir}",
            is_machine_json=args.machine_json,
        )

    progress_callback = None
    if args.progress != "none":

        def progress_callback_func(
            event_type: str, current: int, total: int, message: Optional[str]
        ):
            if args.progress == "detailed":
                if message:
                    logger.info(
                        f"[PROGRESS] {event_type}: {current}/{total} - {message}"
                    )
                else:
                    logger.info(f"[PROGRESS] {event_type}: {current}/{total}")
            else:
                if current >= total:
                    if message:
                        logger.info(f"[DONE] {event_type}: {message}")
                    else:
                        logger.info(f"[DONE] {event_type} complete")

        progress_callback = progress_callback_func

    scanner_threads = 4
    if args.scan:
        import multiprocessing

        scanner_threads = min(multiprocessing.cpu_count() * 2, 8)

    core = SmaliScoutCore(
        target_dir,
        scanner_threads=scanner_threads,
        progress_callback=progress_callback,
        verbose=args.verbose,
    )

    should_save_report = False
    machine_json_output = None

    try:
        if args.manifest:
            core.recon_manifest()
            should_save_report = True

        if args.scan:
            scope = []
            if args.scan in ["vuln", "all"]:
                scope.extend(["files", "webview"])
            if args.scan in ["crypto", "all"]:
                scope.append("crypto")
            if args.scan in ["strings", "all"]:
                scope.append("strings")
            if args.scan in ["integers", "all"]:
                scope.append("integers")
            core.scan_unified(scope)
            should_save_report = True

        if args.brain:
            core.brain(args.brain)
            should_save_report = True

        if args.resource_map:
            core.display_resource_map()

        if args.find_resource:
            core.find_resource_usage(args.find_resource)

        if args.search:
            include_dirs = (
                [d.strip() for d in args.search_in.split(",")]
                if args.search_in
                else None
            )
            exclude_dirs = (
                [d.strip() for d in args.search_exclude.split(",")]
                if args.search_exclude
                else None
            )

            results = core.search(
                query=args.search,
                search_type=args.search_type,
                include_dirs=include_dirs,
                exclude_dirs=exclude_dirs,
                max_results=args.search_max,
                progress_callback=progress_callback,
            )

            if args.machine_json:
                machine_json_output = json.dumps(results, ensure_ascii=False)
            else:
                _display_search_results(results, args.output_format)
                core.report["findings"]["search"] = results
                should_save_report = True

        if args.xref:
            xref_results = core.xref(
                target=args.xref,
                direction=args.xref_direction,
                max_depth=args.xref_depth,
                include_system=args.xref_include_system,
            )
            if args.machine_json:
                machine_json_output = json.dumps(xref_results, ensure_ascii=False)
            else:
                _display_xref_results(xref_results, args.output_format)
                core.report["findings"]["xref"] = xref_results
                should_save_report = True

        if args.hook:
            if args.dry_run:
                _preview_hook(args.hook, core)
            else:
                core.patch_method(args.hook)
                should_save_report = True

        if args.frida:
            core.gen_frida(args.frida)
            should_save_report = True

        if args.cfg:
            core.gen_cfg(args.cfg)
            should_save_report = False

        if args.ui_trace:
            core.trace_ui(args.ui_trace)
            should_save_report = True

        if args.reason:
            core.generate_report_insights()
            should_save_report = True

        if args.translate:
            core.translate_semantic(args.translate)
            should_save_report = True

        if args.generate_hook_class:
            core.generate_hook_class()
            should_save_report = False  # Não afeta o relatório principal

        if args.patch_manifest:
            changes = {}
            for item in args.patch_manifest:
                if "=" not in item:
                    logger.error(
                        f"[MANIFEST] Invalid format: {item}, expected key=value"
                    )
                    sys.exit(1)
                key, value = item.split("=", 1)
                changes[key] = value
            core.patch_manifest(changes)
            should_save_report = True

        if args.scan_rules:
            rules_file = Path(args.scan_rules)
            if not rules_file.exists():
                logger.error(f"[CUSTOM SCAN] Rules file not found: {rules_file}")
                sys.exit(1)
            core.scan_custom_rules(rules_file)
            should_save_report = True

        if args.graph:
            core.export_graph(args.graph)
            should_save_report = (
                False  # Relatório não afetado, mas podemos salvar se quiser
            )

        if args.export or should_save_report:
            core.save_report()

        if machine_json_output:
            print(machine_json_output)

    except KeyboardInterrupt:
        logger.warning("\n[INTERRUPTED] Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        _handle_error(
            ErrorCodes.UNKNOWN_ERROR,
            str(e),
            is_machine_json=args.machine_json,
            exception_type=type(e).__name__,
        )


if __name__ == "__main__":
    main()

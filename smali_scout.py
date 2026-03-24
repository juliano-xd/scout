#!/usr/bin/env python3
import os
import re
import argparse
import json
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict, OrderedDict
from pathlib import Path
from datetime import datetime

# Logging ajustado para clareza
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("ScoutCore")

class LRUCache:
    def __init__(self, capacity=1000):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key):
        if key not in self.cache: return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def put(self, key, value):
        if key in self.cache: self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity: self.cache.popitem(last=False)

    def invalidate(self, key):
        self.cache.pop(key, None)

class SmaliScoutCore:
    def __init__(self, root_dir, cache_size=5000):
        self.root_dir = Path(root_dir).resolve()
        self.smali_dirs = self._get_numeric_smali_dirs()
        self.manifest_path = self._find_manifest()
        
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "target": str(self.root_dir),
            "stats": {"classes": 0},
            "findings": {}
        }
        
        self.class_index = defaultdict(list)
        self.file_cache = LRUCache(capacity=cache_size)
        self._build_index()

    def _get_numeric_smali_dirs(self):
        dirs = [d.name for d in self.root_dir.iterdir() if d.is_dir() and d.name.startswith('smali')]
        def _nk(n):
            if n == 'smali': return 0
            m = re.search(r'smali_classes(\d+)', n)
            return int(m.group(1)) if m else 0
        return sorted(dirs, key=_nk)

    def _find_manifest(self):
        for p in self.root_dir.rglob("AndroidManifest.xml"): return p
        return None

    def _build_index(self):
        logger.info(f"[INDEXER] Scanning: {self.root_dir.name}")
        class_p = re.compile(r'^\.class\s+(?:[^\s]+\s+)*?(L[^;]+;)', re.MULTILINE)
        
        def _task(f):
            try:
                content = f.read_text(encoding='utf-8', errors='ignore')
                match = class_p.search(content)
                if match: return match.group(1), f
            except: pass
            return None

        files = [] 
        for d in self.smali_dirs:
            files.extend(list((self.root_dir / d).rglob("*.smali")))

        with ThreadPoolExecutor() as ex:
            for res in ex.map(_task, files):
                if res:
                    self.class_index[res[0]].append(res[1])
                    self.report["stats"]["classes"] += 1

    def resolve(self, query):
        paths = self.class_index.get(query, [])
        return paths[-1] if paths else None

    def read(self, path):
        c = self.file_cache.get(path)
        if c is None:
            c = path.read_text(encoding='utf-8', errors='ignore')
            self.file_cache.put(path, c)
        return c

    def recon_manifest(self):
        if not self.manifest_path: return
        try:
            root = ET.parse(self.manifest_path).getroot()
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            logger.info(f"[MANIFEST] Recon: {self.manifest_path.name}")
            app = root.find('.//application', namespaces=ns)
            flags = {}
            if app is not None:
                flags = {
                    "debuggable": app.get(f"{{{ns['android']}}}debuggable") == "true",
                    "allowBackup": app.get(f"{{{ns['android']}}}allowBackup") != "false"
                }

            eps = []
            for tag in ['activity', 'service', 'receiver', 'provider']:
                for comp in root.iter(tag):
                    raw_exp = comp.get(f"{{{ns['android']}}}exported")
                    has_filter = comp.find('intent-filter') is not None
                    exported = (raw_exp == "true") or (raw_exp is None and has_filter)
                    
                    if exported:
                        eps.append({"type": tag.upper(), "name": comp.get(f"{{{ns['android']}}}name")})

            logger.info(f" -> Exported: {len(eps)}")
            self.report["findings"]["manifest"] = {"flags": flags, "entry_points": eps}
        except Exception as e: logger.error(f"[ERROR] Manifest: {e}")

    def patch_atomic(self, sig):
        if '->' not in sig: return
        cl, met = sig.split('->', 1)
        path = self.resolve(cl)
        if not path: return logger.error(f"[ERROR] Unresolved: {cl}")

        logger.info(f"[PATCH] Target: {sig}")
        hook_cl = "Lcom/bx/hook/ScoutHook;"
        hook_m = f"on_{re.sub(r'[^a-zA-Z0-9]', '_', met.split('(')[0])}"
        lines = self.read(path).splitlines()

        if any(f"{hook_cl}->{hook_m}" in l for l in lines):
            return logger.info(" -> Already patched. Skipping.")

        new_lines = []
        applied, in_m = False, False
        for l in lines:
            new_lines.append(l)
            if l.startswith(".method") and f" {met}" in l: in_m = True
            if in_m and not applied:
                s = l.strip()
                if any(s.startswith(x) for x in [".locals", ".registers", ".prologue", ".line"]):
                    new_lines.extend([f"    invoke-static {{}}, {hook_cl}->{hook_m}()V"])
                    applied, in_m = True, False

        if applied:
            ts = datetime.now().microsecond
            tmp = path.with_suffix(f'.tmp_{ts}')
            bak = path.with_suffix(f'.bak_{datetime.now().strftime("%H%M%S")}')
            try:
                tmp.write_text("\n".join(new_lines) + "\n", encoding='utf-8')
                os.rename(path, bak)
                os.rename(tmp, path)
                self.file_cache.invalidate(path)
                logger.info(f" -> SUCCESS: {path.name}")
            except Exception as e: logger.error(f"[ERROR] Atomic write: {e}")

    def gen_frida(self, sig):
        cl, met = sig.split('->', 1)
        name = met.split('(')[0]
        logger.info(f"[FRIDA] Mapping: {sig}")
        
        def _parse(s):
            types = re.findall(r'(\[+[ZBSCIJFDV]|\[+[L][^;]+;|[ZBSCIJFDV]|[L][^;]+;)', s)
            res = []
            for t in types:
                if t.startswith('['): res.append(t)
                elif t.startswith('L'): res.append(t[1:-1].replace('/', '.'))
                else: res.append({"Z":"boolean","I":"int","J":"long","V":"void"}.get(t, t))
            return res

        args = _parse(met.split('(')[1].split(')')[0])
        j_cl = cl[1:-1].replace('/', '.')
        script = f"Java.perform(function() {{\n    var c = Java.use('{j_cl}');\n"
        script += f"    c.{name}.overload({', '.join([f'\"{a}\"' for a in args])}).implementation = function() {{\n"
        script += f"        console.log('[HIT] {name}');\n        return this.{name}.apply(this, arguments);\n    }};\n}});"
        
        Path("scout_hook.js").write_text(script, encoding='utf-8')
        logger.info(" -> scout_hook.js created.")

    def scan_unified(self, scope):
        logger.info(f"[SCAN] Scope: {scope}")
        rules = {
            "files": re.compile(r'openFileOutput'),
            "webview": re.compile(r'setJavaScriptEnabled'),
            "crypto": re.compile(r'Cipher|MessageDigest|SecretKeySpec')
        }
        res = defaultdict(set)
        for cl, paths in self.class_index.items():
            content = self.read(paths[-1])
            for k, p in rules.items():
                if p.search(content): res[k].add(cl)
        
        self.report["findings"]["scans"] = {k: list(v) for k, v in res.items()}
        logger.info(f" -> Found: {sum(len(v) for v in res.values())} hits.")

    def brain(self, query):
        path = self.resolve(query)
        if not path: return
        content = self.read(path)
        api_p = re.compile(r'invoke-.* ([L](?:android|java|javax|okhttp|com/google|com/facebook)[^;]+;->[a-zA-Z0-9<>\$-]+)')
        top = Counter(api_p.findall(content)).most_common(5)
        logger.info(f"[BRAIN] {query}")
        for a, c in top: logger.info(f" - {a} ({c}x)")
        self.report["findings"]["brain"] = {query: top}

    def save_report(self):
        Path("scout_report.json").write_text(json.dumps(self.report, indent=4), encoding='utf-8')
        logger.info("[REPORT] Saved to scout_report.json")

def main():
    p = argparse.ArgumentParser(description='SmaliScout Core')
    p.add_argument('--manifest', action='store_true')
    p.add_argument('--scan', choices=['vuln', 'crypto', 'all'])
    p.add_argument('--brain')
    p.add_argument('--hook')
    p.add_argument('--frida')
    p.add_argument('--export', action='store_true')
    
    args = p.parse_args()
    core = SmaliScoutCore(os.getcwd())

    if args.manifest: core.recon_manifest()
    if args.scan:
        s = ['files', 'webview'] if args.scan in ['vuln', 'all'] else []
        if args.scan in ['crypto', 'all']: s.append('crypto')
        core.scan_unified(s)
    
    if args.brain: core.brain(args.brain)
    if args.hook: core.patch_atomic(args.hook)
    if args.frida: core.gen_frida(args.frida)

    if args.export or any([args.manifest, args.scan, args.brain, args.hook, args.frida]):
        core.save_report()

if __name__ == "__main__": main()
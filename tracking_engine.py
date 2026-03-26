import re
import logging
import sys
import pickle
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any

logger = logging.getLogger("ScoutTracking")

def intern_sig(s: str) -> str:
    """Interns a string to save memory for repeated signatures."""
    return sys.intern(s) if isinstance(s, str) else s

class XREFEngine:
    """
    High-performance Cross-Reference engine.
    """
    __slots__ = ['class_index', 'file_cache', 'max_workers', 'progress_callback', 
                 'method_callers', 'method_callees', 'class_references', 'field_accesses']

    RE_CALL = re.compile(r"invoke-\w+\s+{[^}]*},\s*(\[*(?:L[^;]+;|[ZBSCIJFDV])->[^\(]+\([^\)]*\)[^\s]*)")
    RE_FIELD = re.compile(r"(?:i|s)(?:get|put)[^\s]*\s+[^,]+,\s*(\[*(?:L[^;]+;|[ZBSCIJFDV])->[^\s]+)")

    def __init__(self, class_index, file_cache, max_workers=4, progress_callback=None):
        self.class_index = class_index
        self.file_cache = file_cache
        self.max_workers = max_workers
        self.progress_callback = progress_callback
        self.method_callers = defaultdict(set)
        self.method_callees = defaultdict(set)
        self.class_references = defaultdict(set)
        self.field_accesses = defaultdict(set)

    def get_call_graph(self, target: str, depth: int = 1, direction: str = "both") -> Dict:
        """Generates a hierarchical call graph up to the specified depth."""
        target = intern_sig(target)
        graph = {"target": target, "callers": [], "callees": []}
        
        if depth <= 0: return graph
        
        if direction in ["both", "up"]:
            for caller in self.method_callers.get(target, []):
                graph["callers"].append(self.get_call_graph(caller, depth - 1, "up") if depth > 1 else caller)
        
        if direction in ["both", "down"]:
            for callee in self.method_callees.get(target, []):
                graph["callees"].append(self.get_call_graph(callee, depth - 1, "down") if depth > 1 else callee)
                
        return graph

    def save_index(self, path: str = "scout_xref.pkl"):
        """Persists XREF indexes to disk."""
        try:
            data = {
                "callers": dict(self.method_callers),
                "callees": dict(self.method_callees),
                "refs": dict(self.class_references),
                "fields": dict(self.field_accesses)
            }
            with open(path, "wb") as f:
                pickle.dump(data, f)
            logger.info(f"[XREF] Index persisted to {path}")
        except Exception as e:
            logger.error(f"[XREF] Failed to save index: {e}")

    def load_index(self, path: str = "scout_xref.pkl") -> bool:
        """Loads XREF indexes from disk if available."""
        p = Path(path)
        if not p.exists(): return False
        try:
            with open(p, "rb") as f:
                data = pickle.load(f)
            self.method_callers = defaultdict(set, data["callers"])
            self.method_callees = defaultdict(set, data["callees"])
            self.class_references = defaultdict(set, data["refs"])
            self.field_accesses = defaultdict(set, data["fields"])
            logger.info(f"[XREF] Loaded index from {path}")
            return True
        except Exception as e:
            logger.error(f"[XREF] Failed to load index: {e}")
            return False

    def build_indexes(self):
        if self.load_index(): return
        
        logger.info("[XREF] Building high-performance indexes...")
        class_path_pairs = [(intern_sig(cl), paths[-1]) for cl, paths in self.class_index.items() if paths]
        total = len(class_path_pairs)
        
        # Use a chunked approach for better thread utilization
        chunk_size = max(10, total // (self.max_workers * 4))
        chunks = [class_path_pairs[i:i + chunk_size] for i in range(0, total, chunk_size)]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_chunk = {executor.submit(self._analyze_chunk, chunk): i for i, chunk in enumerate(chunks)}
            for i, future in enumerate(as_completed(future_to_chunk)):
                result_list = future.result()
                for result in result_list:
                    if result: self._merge_xref_data(result)
                if self.progress_callback:
                    self.progress_callback("xref_building", min(i*chunk_size, total), total, f"Indexing {i*chunk_size}/{total}")
        
        self.save_index()

    def _analyze_chunk(self, chunk: List[Tuple[str, Path]]) -> List[Dict]:
        results = []
        for cl, path in chunk:
            result = self._analyze_class(cl, path)
            if result is not None:
                results.append(result)
        return results

    def _analyze_class(self, class_name: str, path: Path) -> Optional[Dict]:
        content = self.file_cache.get(path)
        if not content:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except (IOError, OSError, PermissionError, UnicodeDecodeError):
                # Bug #15 fix: Catch specific exceptions instead of bare except
                return None

        data = {"class": class_name, "calls": set(), "refs": set(), "fields": set()}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith((".", "#")): continue
            
            # Fast Dispatch Optimization
            if "invoke-" in line:
                m = self.RE_CALL.search(line)
                if m:
                    call = intern_sig(m.group(1))
                    data["calls"].add(call)
                    cls = intern_sig(call.partition("->")[0])
                    if cls != class_name: data["refs"].add(cls)
            elif "get-" in line or "put-" in line:
                m = self.RE_FIELD.search(line)
                if m:
                    f_sig = intern_sig(m.group(1))
                    data["fields"].add(f_sig)
                    cls = intern_sig(f_sig.partition("->")[0])
                    if cls != class_name: data["refs"].add(cls)
            elif "const-class" in line:
                # Extract L...; from const-class v0, L...;
                parts = line.split(",")
                if len(parts) > 1:
                    cls = intern_sig(parts[1].strip())
                    if cls != class_name: data["refs"].add(cls)
        return data

    def _merge_xref_data(self, data):
        cl = data["class"]
        for call in data["calls"]:
            self.method_callees[cl].add(call)
            self.method_callers[call].add(cl)
        self.class_references[cl].update(data["refs"])
        self.field_accesses[cl].update(data["fields"])

    def get_polymorphic_xrefs(self, method_sig: str, inheritance_engine) -> Set[str]:
        method_sig = intern_sig(method_sig)
        callers = self.method_callers[method_sig].copy()
        if inheritance_engine:
            cls, _, met = method_sig.partition("->")
            for sub in inheritance_engine.get_subclasses(cls):
                callers.update(self.method_callers[intern_sig(f"{sub}->{met}")])
        return callers

class TaintEngine:
    """
    Consolidated Data Flow & Taint Analysis Engine.
    """
    __slots__ = ['kb']

    RE_CONST = re.compile(r'const-string(?:/jumbo)?\s+([vp0-9]+),\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
    RE_CONST_INT = re.compile(r'const(?:/4|/16|/high16)?\s+([vp0-9]+),\s+(-?0x[a-fA-F0-9]+|-?\d+)')
    RE_INVOKE = re.compile(r"invoke-[^\s]+\s+({[^}]*}),\s*(L[^;]+;->[^\s]+)")

    def __init__(self, knowledge_base=None):
        self.kb = knowledge_base

    def analyze_method(self, body: List[str]) -> Dict[str, Set[str]]:
        track_map = defaultdict(set)
        field_map = defaultdict(set)
        # Bug #9 fix: Initialize last_invoke_sig to avoid UnboundLocalError
        last_invoke_sig = None

        for line in body:
            line = line.strip()
            if not line or line.startswith((".", "#")): continue

            # Fast dispatch
            if line.startswith("const-string"):
                m = self.RE_CONST.match(line)
                if m:
                    reg, val = m.groups()
                    dt = self._infer_type(val)
                    if dt: track_map[reg].add(intern_sig(f"SRC:{dt}"))
            
            elif line.startswith("const"):
                m = self.RE_CONST_INT.match(line)
                if m:
                    reg, val = m.groups()
                    track_map[reg].add(intern_sig(f"SRC:VAL:{val}"))
            
            elif line.startswith("invoke"):
                parts = line.split()
                if len(parts) >= 3:
                    target = parts[-1]
                    sig = intern_sig(target)
                    regs_raw = line[line.find("{")+1 : line.find("}")]
                    regs = [r.strip() for r in regs_raw.split(",") if r.strip()]
                    
                    # Mark sinks
                    for i, r in enumerate(regs):
                        if track_map[r]: 
                            track_map[r].add(intern_sig(f"SNK:{target}(arg{i})"))
                    
                    # Prepare for move-result (capture the source)
                    last_invoke_sig = sig

            elif line.startswith("move-result"):
                # Captura o retorno da última chamada como uma fonte (SRC)
                if last_invoke_sig:
                    parts = line.split()
                    if len(parts) >= 2:
                        dst = parts[1].rstrip(",")
                        track_map[dst].add(intern_sig(f"SRC:{last_invoke_sig}"))
                        last_invoke_sig = None
            
            elif line.startswith("move"):
                parts = line.split()
                if len(parts) >= 3:
                    dst = parts[1].rstrip(",")
                    src = parts[2]
                    if track_map[src]: track_map[dst].update(track_map[src])
            
            elif "get-" in line or "put-" in line:
                if "->" in line:
                    parts = line.split(",")
                    f_sig = intern_sig(parts[-1].strip())
                    reg = parts[0].split()[-1]
                    if "get-" in line:
                        if field_map[f_sig]: track_map[reg].update(field_map[f_sig])
                        track_map[reg].add(intern_sig(f"FLD:{f_sig}"))
                    else: # put
                        if track_map[reg]: field_map[f_sig].update(track_map[reg])
        
        return {k: v for k, v in track_map.items() if v}

    def suggest_name(self, reg: str, history) -> str:
        # Priority-based naming: Sources > Fields > Sinks
        # Bug #12 fix: Accept both Set[str] and List[str]
        if not isinstance(history, (set, list)):
            history = set()
        for h in history:
            if "URL" in h: return f"url_{reg}"
        for h in history:
            if "B64" in h: return f"base64_{reg}"
        for h in history:
            if "FLD:" in h: return intern_sig(h.split("->")[-1].partition(":")[0].partition("->")[-1].lower()) + f"_{reg}"
        for h in history:
            if "SNK:" in h:
                target = intern_sig(h.split("->")[-1].split("(")[0])
                return f"var_{target}_{reg}"
        return f"var_{reg}"

    def _infer_type(self, val: str) -> Optional[str]:
        if val.startswith(("http://", "https://")): return "URL"
        if len(val) >= 12 and re.match(r'^[A-Za-z0-9+/=]+$', val): 
            # Check for typical B64 padding or lack of too many non-alphanumeric if no padding
            if val.endswith("=") or len(set(val) & set("+/")) > 0:
                return "B64"
            # Generic long alphanumeric is often a key or token
            if len(val) >= 24:
                return "B64"
        return None

class TrackingEngine:
    def __init__(self, class_index, file_cache, kb=None):
        self.xref = XREFEngine(class_index, file_cache)
        self.taint = TaintEngine(kb)
        
    def perform_full_taint_scan(self, scout_core, apis_found: Dict[str, List[Dict]]) -> List[Dict]:
        results = []
        processed = set()
        for locations in apis_found.values():
            for loc in locations:
                m_sig = intern_sig(f"{loc['class']}->{loc['method']}")
                if m_sig in processed: continue
                
                body = scout_core._get_method_body(m_sig)
                if not body: continue
                
                dfa = self.taint.analyze_method(body)
                for reg, history in dfa.items():
                    sources = [h for h in history if h.startswith("SRC:")]
                    sinks = [h for h in history if h.startswith("SNK:")]
                    if sources and sinks:
                        for src in sources:
                            for snk in sinks:
                                results.append({
                                    "method": m_sig,
                                    "src": src.replace("SRC:", ""),
                                    "sink": snk.replace("SNK:", ""),
                                    "reg": reg
                                })
                processed.add(m_sig)
        return results

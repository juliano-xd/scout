#!/usr/bin/env python3

import re
import logging
from collections import defaultdict
from typing import List, Dict, Optional, Set

logger = logging.getLogger("ScoutSemantic")

class SemanticEngine:
    """
    Translates Smali bytecode into simplified, high-level Pseudocode.
    Optimized for AI consumption with maximum logical fidelity.
    """

    def __init__(self):
        # Rules with capture groups and specialized handlers
        self.rules = [
            # Arithmetic/Binary Ops (add-int, sub-long, xor-int/2addr, etc.)
            (re.compile(r'^\s*(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-([^\s/]+)(?:/2addr)?\s+([vp0-9]+),\s+(?:([vp0-9]+),\s+)?(.*)'), self._handle_arithmetic),
            # Array Ops
            (re.compile(r'^\s*(?:new-array)\s+([vp0-9]+),\s+([vp0-9]+),\s+(L[^;]+;)'), r'\1 = new \3[\2]'),
            (re.compile(r'^\s*(?:aget|aput)([^\s]*)\s+([vp0-9]+),\s+([vp0-9]+),\s+([vp0-9]+)'), self._handle_array_access),
            # Field access
            (re.compile(r'^\s*(?:sget|sput)([^\s]*)\s+([vp0-9]+),\s*(L[^;]+;->[^\s]+)'), self._handle_field),
            (re.compile(r'^\s*(?:iget|iput)([^\s]*)\s+([vp0-9]+),\s+([vp0-9]+),\s*(L[^;]+;->[^\s]+)'), self._handle_field),
            # Object creation
            (re.compile(r'^\s*new-instance\s+([vp0-9]+),\s+(L[^;]+;)'), r'\1 = new \2()'),
            (re.compile(r'^\s*check-cast\s+([vp0-9]+),\s+(L[^;]+;)'), r'# cast \1 to \2'),
            # Constants and Moves
            (re.compile(r'^\s*const-string[^\s]*\s+([vp0-9]+),\s*"([^"]+)"'), r'\1 = "\2"'),
            (re.compile(r'^\s*const[^\s]*\s+([vp0-9]+),\s+([x0-9a-fA-F-]+)'), r'\1 = \2'),
            (re.compile(r'^\s*move[^\s]*\s+([vp0-9]+),\s+([vp0-9]+)'), r'\1 = \2'),
            (re.compile(r'^\s*move-exception\s+([vp0-9]+)'), r'\1 = caught_exception'),
            # Flow control
            (re.compile(r'^\s*if-([^\s]+)\s+([vp0-9]+),\s+([vp0-9]+),\s*([:[^\s]+)'), r'if (\2 \1 \3) goto \4'),
            (re.compile(r'^\s*if-([^\s]+)z\s+([vp0-9]+),\s*([:[^\s]+)'), r'if (\2 \1 0) goto \3'),
            (re.compile(r'^\s*return[^\s]*\s+([vp0-9]+)'), r'return \1'),
            (re.compile(r'^\s*return-void'), 'return'),
            (re.compile(r'^\s*goto[^\s]*\s+([:[^\s]+)'), r'goto \1'),
            (re.compile(r'^\s*(:[^\s]+)'), r'LABEL \1:'),
        ]
        self.INVOKE_RE = re.compile(r"^\s*invoke-[^\s]+\s+({[^}]*}|([vp0-9]+)\s*\.\.\.\s*([vp0-9]+)),\s*(L[^;]+;->[^\s]+)")

    def _handle_arithmetic(self, match) -> str:
        op, _, dst, src1, src2 = match.groups()
        op_map = {"add": "+", "sub": "-", "mul": "*", "div": "/", "rem": "%", "and": "&", "or": "|", "xor": "^", "shl": "<<", "shr": ">>", "ushr": ">>>"}
        symbol = op_map.get(op, op)
        if src1 is None: # 2addr format
            return f"{dst} = {dst} {symbol} {src2}"
        return f"{dst} = {src1} {symbol} {src2}"

    def _handle_array_access(self, match) -> str:
        _, val, arr, idx = match.groups()
        if "aput" in match.group(0):
            return f"{arr}[{idx}] = {val}"
        return f"{val} = {arr}[{idx}]"

    def _handle_field(self, match) -> str:
        groups = match.groups()
        if len(groups) == 3: # Static access
            _, reg, field_sig = groups
            if "sput" in match.group(0): return f"static_field[{field_sig}] = {reg}"
            return f"{reg} = static_field[{field_sig}]"
        else: # Instance access
            _, reg, obj, field_sig = groups
            field_name = field_sig.split("->")[-1]
            if "iput" in match.group(0): return f"{obj}.{field_name} = {reg}"
            return f"{reg} = {obj}.{field_name}"

    def _clean_signature(self, sig: str, inheritance_engine = None) -> str:
        if not sig.startswith("L"): return sig
        if inheritance_engine:
            label = inheritance_engine.identify_type(sig)
            if label: return label
        return sig[1:-1].split("/")[-1]

    def _simplify_invoke(self, line: str, name_map: Dict[str, str], inheritance_engine=None) -> Optional[str]:
        match = self.INVOKE_RE.match(line)
        if not match: return None
        full_regs, range_start, range_end, sig = match.groups()
        if range_start and range_end:
            prefix = range_start[0]
            regs = [f"{prefix}{i}" for i in range(int(range_start[1:]), int(range_end[1:]) + 1)]
        else:
            regs = [r.strip() for r in full_regs.strip("{}").split(",")]
        try:
            class_part, method_all = sig.split("->", 1)
            method_name = method_all.split("(")[0]
            clean_class = self._clean_signature(class_part, inheritance_engine)
            named_regs = [name_map.get(r, r) for r in regs if r]
            if not named_regs: return f"{clean_class}.{method_name}()"
            if "static" in line: return f"{clean_class}.{method_name}({', '.join(named_regs)})"
            obj = named_regs[0]
            args = ", ".join(named_regs[1:])
            return f"{obj}.{method_name}({args})"
        except Exception: return f"call {sig} with {regs}"

    def _is_register_in_string(self, line: str, reg: str) -> bool:
        """Check if a register appears inside a string literal in the line."""
        eq_pos = line.find('=')
        if eq_pos == -1:
            return False
        
        after_eq = line[eq_pos+1:]
        quote_positions = [i for i, c in enumerate(after_eq) if c == '"']
        if len(quote_positions) < 2:
            return False
        
        reg_pos = after_eq.find(reg)
        if reg_pos == -1:
            return False
        
        in_string = False
        for qpos in quote_positions:
            if qpos < reg_pos:
                in_string = not in_string
            else:
                break
        
        return in_string

    def _fold_statements(self, translated: List[str]) -> List[str]:
        if len(translated) < 2: return translated
        folded = []
        i = 0
        while i < len(translated):
            line = translated[i]
            match = re.match(r'^([vp0-9]+)\s*=\s*(.*)$', line)
            if match and i + 1 < len(translated):
                reg, val = match.groups()
                next_line = translated[i+1]
                # Safe folding: use regex boundaries \b for robust usage check
                if re.search(rf'\b{reg}\b', next_line) and not next_line.startswith(f"{reg} ="):
                    # Bug #10 fix: Check if register is inside string literal
                    if self._is_register_in_string(next_line, reg):
                        i += 1
                        folded.append(line)
                        continue

                    remaining = " ".join(translated[i+2:])
                    if not re.search(rf'\b{reg}\b', remaining):
                        folded.append(re.sub(rf'\b{reg}\b', val, next_line))
                        i += 2
                        continue
            folded.append(line)
            i += 1
        return folded

    def _translate_block(self, block_instructions: List[str], name_map: Dict[str, str], inheritance_engine=None, last_invoke_container: List = None) -> List[str]:
        """Translates a single basic block's instructions."""
        translated = []
        for line in block_instructions:
            clean = line.strip()
            if not clean or any(clean.startswith(x) for x in ["#", ".local", ".method", ".registers", ".locals", ".end"]):
                continue

            if "move-result" in clean:
                res_reg = clean.split()[1]
                target_name = name_map.get(res_reg, res_reg)
                if last_invoke_container and last_invoke_container[0]:
                    lst, idx = last_invoke_container[0]
                    # lst[idx] is [prefix, result_text]
                    lst[idx][1] = f"{target_name} = {lst[idx][1]}"
                    last_invoke_container[0] = None # Applied
                continue

            found_match = False
            for pattern, action in self.rules:
                match = pattern.match(clean)
                if match:
                    if callable(action): result = action(match)
                    else: result = pattern.sub(action, clean)
                    for reg, name in name_map.items(): 
                        result = re.sub(rf'\b{reg}\b', name, result)
                    
                    # Fix operators for pseudo-logic
                    ops = {" eq ": " == ", " ne ": " != ", " lt ": " < ", " ge ": " >= ", " gt ": " > ", " le ": " <= "}
                    for k, v in ops.items(): result = result.replace(k, v)
                    translated.append(result)
                    found_match = True
                    break
            
            if not found_match:
                invoke_str = self._simplify_invoke(clean, name_map, inheritance_engine)
                if invoke_str:
                    translated.append(invoke_str)
        return translated

    def translate_method(self, method_body: List[str], dfa_results: Optional[Dict[str, List[str]]] = None, inheritance_engine = None) -> str:
        """
        Translates Smali into STRUCTURED Pseudocode.
        """
        from cfg_engine import CFGEngine
        cfg_eng = CFGEngine()
        blocks = cfg_eng.build_cfg(method_body)
        
        name_map = {}
        if dfa_results:
            from tracking_engine import TaintEngine as RegisterTracker
            temp_tracker = RegisterTracker()
            for pX, usages in dfa_results.items():
                suggested = temp_tracker.suggest_name(pX, usages)
                if suggested != pX: name_map[pX] = f"{suggested}_{pX}"

        # Parse Metadata (Exceptions & Switches)
        exception_table = []
        switch_tables = {} # table_label -> { val: target_label }
        
        catch_re = re.compile(r"^\s*\.catch\s+(L[^;]+;|all)\s+({(:[^\s]+)\s*\.\.\s*(:[^\s]+)})\s+([:[^\s]+)")
        in_switch = None
        current_case_val = 0

        for i, line in enumerate(method_body):
            clean = line.strip()
            # Catch
            cm = catch_re.match(clean)
            if cm:
                etype, _, start, end, handler = cm.groups()
                exception_table.append({"type": etype, "start": start, "end": end, "handler": handler})
            
            # Switch Table
            if ".packed-switch" in clean:
                prev_line = method_body[i-1].strip() if i > 0 else ""
                label_m = re.match(r"^\s*(:[^\s]+)", prev_line)
                if label_m:
                    label = label_m.group(1)
                    in_switch = (label, "packed")
                    switch_tables[label] = {}
                    val_match = re.search(r"0x[0-9a-fA-F]+", clean)
                    current_case_val = int(val_match.group(0), 16) if val_match else 0
            elif ".sparse-switch" in clean:
                prev_line = method_body[i-1].strip() if i > 0 else ""
                label_m = re.match(r"^\s*(:[^\s]+)", prev_line)
                if label_m:
                    label = label_m.group(1)
                    in_switch = (label, "sparse")
                    switch_tables[label] = {}
            elif ".end packed-switch" in clean or ".end sparse-switch" in clean:
                in_switch = None
            elif in_switch:
                label, sw_type = in_switch
                target_m = re.search(r"(:[^\s]+)", clean)
                if target_m:
                    target = target_m.group(1)
                    if sw_type == "sparse":
                        val_m = re.search(r"(-?0x[0-9a-fA-F]+|-?\d+)", clean)
                        val = val_m.group(0) if val_m else str(current_case_val)
                        switch_tables[label][val] = target
                    else:
                        switch_tables[label][str(current_case_val)] = target
                        current_case_val += 1

        final_output = []
        indent_level = 0
        block_list = sorted(blocks.values(), key=lambda b: b.id if b.id != "entry" else "0_entry")
        processed_blocks = set()

        def emit(text, level, is_invoke=False):
            final_output.append(["    " * level, text])
            if is_invoke:
                last_invoke_container[0] = (final_output, len(final_output) - 1)

        active_tries = set()
        emitted_handlers = set()
        last_invoke_container = [None] # [ (list, index) ]
        for b in block_list:
            if b.id in processed_blocks: continue
            
            # Group exception table
            ranges = defaultdict(list)
            for entry in exception_table:
                ranges[(entry["start"], entry["end"])].append(entry)

            # Try start
            for (start, end), entries in ranges.items():
                if any(start in inst for inst in b.instructions) and start not in active_tries:
                    emit(f"try {{ # [REGION {start}]", indent_level)
                    indent_level += 1
                    active_tries.add(start)
                
                # Handlers (match precisely and only once)
                for entry in entries:
                    handler_id = f"{start}_{end}_{entry['handler']}_{entry['type']}"
                    if handler_id not in emitted_handlers:
                        if any(inst.strip().startswith(entry["handler"]) for inst in b.instructions):
                            if indent_level > 0: indent_level -= 1
                            emit(f"}} catch ({entry['type']}) {{", indent_level)
                            indent_level += 1
                            emitted_handlers.add(handler_id)

            # Switch Handling emit
            for inst in b.instructions:
                sw_match = re.search(r"(packed|sparse)-switch\s+([vp0-9]+),\s+(:[^\s]+)", inst)
                if sw_match:
                    _, reg, table_label = sw_match.groups()
                    target_name = name_map.get(reg, reg)
                    emit(f"switch({target_name}) {{ # using {table_label}", indent_level)
                    indent_level += 1
                    break
            
            # Case labels emit
            for table_label, cases in switch_tables.items():
                for val, target_label in cases.items():
                    if any(target_label in inst for inst in b.instructions):
                        if indent_level > 0: indent_level -= 1
                        emit(f"case {val}:", indent_level)
                        indent_level += 1

            # Translate block logic
            translated_lines = self._translate_block(b.instructions, name_map, inheritance_engine, last_invoke_container)
            if translated_lines:
                last_line = translated_lines[-1]
                if "if (" in last_line:
                    emit(last_line.replace("goto", "{"), indent_level)
                    for bline in translated_lines[:-1]: 
                        is_inv = "(" in bline and "=" not in bline
                        emit(bline, indent_level + 1, is_invoke=is_inv)
                    indent_level += 1
                else:
                    for bline in translated_lines: 
                        is_inv = "(" in bline and "=" not in bline
                        emit(bline, indent_level, is_invoke=is_inv)
                    if "return" in last_line or "goto" in last_line:
                        if indent_level > 0:
                            indent_level -= 1
                            emit("}", indent_level)

            # Close try regions
            for entry in exception_table:
                if any(entry["end"] in inst for inst in b.instructions):
                    if indent_level > 0: indent_level -= 1
                    emit("} # [END TRY]", indent_level)

            processed_blocks.add(b.id)
        
        raw_result = "\n".join(["".join(parts) for parts in final_output])
        folded_lines = self._fold_statements(raw_result.split("\n"))
        return "\n".join(folded_lines)

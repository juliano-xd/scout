#!/usr/bin/env python3

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple

logger = logging.getLogger("ScoutCFG")

@dataclass
class BasicBlock:
    id: str
    instructions: List[str] = field(default_factory=list)
    successors: Set[str] = field(default_factory=set)
    is_entry: bool = False
    is_exit: bool = False

class CFGEngine:
    """
    Engine for building Control Flow Graphs (CFG) from Smali methods.
    Identifies basic blocks and transitions (jumps, branches, returns).
    """

    def __init__(self):
        # Patterns for control flow
        self.LABEL_RE = re.compile(r"^\s*(:[^\s]+)")
        self.IF_RE = re.compile(r"^\s*if-[^\s]+\s+[^,]+,\s*(?:[^,]+,\s*)?([:[^\s]+)")
        self.GOTO_RE = re.compile(r"^\s*goto[^\s]*\s+([:[^\s]+)")
        # Simple switch support (packed-switch / sparse-switch labels)
        self.SWITCH_RE = re.compile(r"^\s*(?:packed|sparse)-switch\s+[^,]+,\s*([:[^\s]+)")
        self.RETURN_RE = re.compile(r"^\s*return")
        self.THROW_RE = re.compile(r"^\s*throw")
        self.CATCH_RE = re.compile(r"^\s*\.catch\s+(L[^;]+;|all)\s+\{(:[^\s]+)\s*\.\.\s*(:[^\s]+)\}\s+(:[^\s]+)")

    def build_cfg(self, method_body: List[str]) -> Dict[str, BasicBlock]:
        """
        Builds the CFG including exception and switch handling paths.
        """
        blocks: Dict[str, BasicBlock] = {}
        current_block = BasicBlock(id="entry", is_entry=True)
        blocks[current_block.id] = current_block
        
        label_to_block: Dict[str, str] = {}
        pending_edges: List[Tuple[str, str]] = [] 
        exception_table: List[Dict] = []
        switch_tables: Dict[str, List[str]] = {} # label -> target_labels

        # First pass: labels, catches, and switch data
        in_switch = None
        for i, line in enumerate(method_body):
            clean = line.strip()
            label_match = self.LABEL_RE.match(clean)
            if label_match:
                label = label_match.group(1)
                label_to_block[label] = f"block_{i}"
                if in_switch: switch_tables[in_switch].append(label)

            if clean.startswith(".packed-switch") or clean.startswith(".sparse-switch"):
                # Find the label that precedes this data block
                # Usually Smali puts the label right before the .switch
                prev_line = method_body[i-1].strip() if i > 0 else ""
                m = self.LABEL_RE.match(prev_line)
                if m: in_switch = m.group(1); switch_tables[in_switch] = []
            elif clean.startswith(".end packed-switch") or clean.startswith(".end sparse-switch"):
                in_switch = None
            elif in_switch and clean.startswith(":") and not clean.startswith(":pswitch"):
                # Sparse switch rows or packed targets
                m = self.LABEL_RE.search(clean)
                if m: switch_tables[in_switch].append(m.group(0))
            
            # Catch parsing
            catch_match = self.CATCH_RE.match(clean)
            if catch_match:
                etype, start, end, handler = catch_match.groups()
                exception_table.append({"type": etype, "start": start, "end": end, "handler": handler})

        # Second pass: build blocks and standard edges
        current_block = blocks["entry"]
        for i, line in enumerate(method_body):
            clean_line = line.strip()
            # Skip metadata and switch data blocks in instruction list
            if not clean_line or clean_line.startswith("#") or clean_line.startswith(".catch") or \
               clean_line.startswith(".packed-switch") or clean_line.startswith(".sparse-switch") or \
               clean_line.startswith(".end packed-switch") or clean_line.startswith(".end sparse-switch"):
                continue

            label_match = self.LABEL_RE.match(clean_line)
            if label_match:
                new_id = label_to_block[label_match.group(1)]
                if current_block.instructions and current_block.id != new_id:
                    current_block.successors.add(new_id)
                current_block = blocks.get(new_id, BasicBlock(id=new_id))
                blocks[new_id] = current_block
                current_block.instructions.append(clean_line)
                continue

            current_block.instructions.append(clean_line)

            # Transitions
            if_match = self.IF_RE.match(clean_line)
            if if_match:
                pending_edges.append((current_block.id, if_match.group(1)))
                next_id = f"block_{i}_next"; current_block.successors.add(next_id)
                current_block = BasicBlock(id=next_id); blocks[next_id] = current_block
                continue

            goto_match = self.GOTO_RE.match(clean_line)
            if goto_match:
                pending_edges.append((current_block.id, goto_match.group(1)))
                current_block = BasicBlock(id=f"block_{i}_dead"); blocks[current_block.id] = current_block
                continue

            switch_match = self.SWITCH_RE.match(clean_line)
            if switch_match:
                table_label = switch_match.group(1)
                for target in switch_tables.get(table_label, []):
                    pending_edges.append((current_block.id, target))
                # Switch has implicit flow to next (default case)
                next_id = f"block_{i}_next"; current_block.successors.add(next_id)
                current_block = BasicBlock(id=next_id); blocks[next_id] = current_block
                continue

            if self.RETURN_RE.match(clean_line) or self.THROW_RE.match(clean_line):
                current_block.is_exit = True
                current_block = BasicBlock(id=f"block_{i}_dead"); blocks[current_block.id] = current_block
                continue

        # Resolve jumps
        for src_id, label in pending_edges:
            if label in label_to_block:
                blocks[src_id].successors.add(label_to_block[label])

        # Exception edges
        for entry in exception_table:
            handler_block = label_to_block.get(entry["handler"])
            if not handler_block: continue
            
            # Precise mapping: find which blocks fall within the instruction index range [start, end)
            try:
                start_idx = int(label_to_block[entry["start"]].split("_")[1])
                end_idx = int(label_to_block[entry["end"]].split("_")[1])
                
                for b_id, b in blocks.items():
                    if b_id.startswith("block_"):
                        # Extract the base instruction index from the block ID
                        parts = b_id.split("_")
                        if len(parts) >= 2 and parts[1].isdigit():
                            b_idx = int(parts[1])
                            if start_idx <= b_idx < end_idx:
                                b.successors.add(handler_block)
            except (KeyError, ValueError, IndexError):
                continue

        return {k: v for k, v in blocks.items() if v.instructions or v.id == "entry"}

    def to_dot(self, blocks: Dict[str, BasicBlock], method_name: str) -> str:
        """
        Exports the CFG to Graphviz DOT format.
        """
        dot = [f'digraph "{method_name}" {{']
        dot.append('    node [shape=box, fontname="Courier", fontsize=10];')
        
        for b_id, block in blocks.items():
            content = "\\l".join([l.replace('"', '\\"') for l in block.instructions[:10]])
            if len(block.instructions) > 10:
                content += "\\l... (truncated)"
            
            color = "lightblue" if block.is_entry else ("lightcoral" if block.is_exit else "white")
            dot.append(f'    "{b_id}" [label="{content}\\l", style=filled, fillcolor={color}];')
            
            for succ in block.successors:
                if succ in blocks:
                    dot.append(f'    "{b_id}" -> "{succ}";')
        
        dot.append("}")
        return "\n".join(dot)

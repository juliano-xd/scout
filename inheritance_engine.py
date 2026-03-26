import re
import logging
import sys
from pathlib import Path
from collections import defaultdict, deque
from typing import List, Dict, Set, Optional, Tuple

logger = logging.getLogger("ScoutInheritance")

def intern_sig(s: str) -> str:
    """Interns a string to save memory for repeated signatures."""
    return sys.intern(s) if isinstance(s, str) else s

class InheritanceEngine:
    """
    Engine for tracking class inheritance and hierarchy in Smali projects.
    """

    def __init__(self, class_index: Dict[str, List[Path]], read_callback, knowledge_base=None):
        self.class_index = class_index
        self.read_callback = read_callback
        self.kb = knowledge_base
        # Cache for direct inheritance: class -> super_class
        self.inheritance_map: Dict[str, str] = {}
        # Map class -> Set of directly implemented interfaces
        self.interfaces_map: Dict[str, Set[str]] = defaultdict(set)
        # New: reverse mapping for subclass lookup
        self.subclasses_map: Dict[str, Set[str]] = defaultdict(set)
        
        # Result caches for expensive lookups
        self._hierarchy_cache: Dict[str, List[str]] = {}
        self._instance_cache: Dict[Tuple[str, str], bool] = {}

    def add_direct_inheritance(self, class_name: str, super_class: str):
        """Adds a direct inheritance relationship with interning."""
        c = intern_sig(class_name)
        s = intern_sig(super_class)
        self.inheritance_map[c] = s
        self.subclasses_map[s].add(c)

    def add_interface(self, class_name: str, interface: str):
        """Adds a direct interface implementation."""
        c = intern_sig(class_name)
        i = intern_sig(interface)
        self.interfaces_map[c].add(i)

    def get_super(self, class_name: str) -> Optional[str]:
        return self.inheritance_map.get(intern_sig(class_name))

    def get_interfaces(self, class_name: str, recursive: bool = False) -> Set[str]:
        """Resolves direct (and optionally indirect) interfaces."""
        class_name = intern_sig(class_name)
        direct = self.interfaces_map.get(class_name, set())
        if not recursive: return direct
        
        all_interfaces = set(direct)
        # We also need to get interfaces from all super-classes
        current = class_name
        while current:
            super_cl = self.get_super(current)
            if not super_cl: break
            all_interfaces.update(self.interfaces_map.get(super_cl, set()))
            current = super_cl
        return all_interfaces

    def get_subclasses(self, class_name: str, recursive: bool = True) -> Set[str]:
        """Resolves all direct and indirect subclasses of a given class."""
        class_name = intern_sig(class_name)
        subs = self.subclasses_map.get(class_name, set())
        if not recursive: return subs
        
        all_subs = set(subs)
        # Use a stack for iterative recursion to avoid recursion depth issues
        stack = list(subs)
        while stack:
            curr = stack.pop()
            children = self.subclasses_map.get(curr, set())
            for child in children:
                if child not in all_subs:
                    all_subs.add(child)
                    stack.append(child)
        return all_subs

    def get_hierarchy(self, class_name: str, max_depth: int = 10) -> List[str]:
        class_name = intern_sig(class_name)
        if class_name in self._hierarchy_cache:
            return self._hierarchy_cache[class_name]
            
        hierarchy = []
        current = class_name
        depth = 0
        
        while current and depth < max_depth:
            super_cl = self.get_super(current)
            if not super_cl: break
            hierarchy.append(super_cl)
            current = super_cl
            depth += 1
            
        self._hierarchy_cache[class_name] = hierarchy
        return hierarchy

    def is_instance_of(self, class_name: str, target_base: str, max_depth: int = 20) -> bool:
        """
        Checks if class_name inherits from or implements target_base.
        Uses BFS for robust recursive interface and inheritance checks.
        """
        class_name = intern_sig(class_name)
        target_base = intern_sig(target_base)
        key = (class_name, target_base)
        if key in self._instance_cache:
            return self._instance_cache[key]
            
        if class_name == target_base:
            return True
            
        # BFS search through the class hierarchy (supers and interfaces)
        # Bug #8 fix: Use deque instead of list for O(1) popleft
        queue = deque([class_name])
        seen = {class_name}
        depth_map = {class_name: 0}
        result = False
        
        while queue:
            curr = queue.popleft()
            depth = depth_map[curr]
            
            if curr == target_base:
                result = True
                break
                
            if depth >= max_depth:
                continue
                
            # 1. Add Direct Super
            sup = self.get_super(curr)
            if sup and sup not in seen:
                seen.add(sup)
                depth_map[sup] = depth + 1
                queue.append(sup)
                
            # 2. Add Direct Interfaces
            for interface in self.interfaces_map.get(curr, set()):
                if interface not in seen:
                    seen.add(interface)
                    depth_map[interface] = depth + 1
                    queue.append(interface)
            
        self._instance_cache[key] = result
        return result

    def identify_type(self, class_name: str) -> Optional[str]:
        """Attempts to identify if a class belongs to well-known Android/Java types."""
        class_name = intern_sig(class_name)
        # 1. Direct match in DB
        if self.kb:
            label = self.kb.get_framework_label(class_name)
            if label: return label

        # 2. Match in hierarchy via DB
        hierarchy = self.get_hierarchy(class_name)
        for base_cl in hierarchy:
            if self.kb:
                label = self.kb.get_framework_label(base_cl)
                if label: return label
        
        return None

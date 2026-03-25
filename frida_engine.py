import re
import logging
from pathlib import Path
from typing import List, Dict, Optional

from tracking_engine import TaintEngine as RegisterTracker
from inheritance_engine import InheritanceEngine

logger = logging.getLogger("ScoutFrida")

class FridaEngine:
    """
    Engine for generating precise and smart Frida hook scripts from Smali signatures.
    Separated from the core to allow complex logic optimization.
    """
    
    PRIMITIVE_MAP = {
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
        "V": "void",
    }

    def __init__(self, inheritance_engine: Optional[InheritanceEngine] = None):
        kb = inheritance_engine.kb if inheritance_engine else None
        self.tracker = RegisterTracker(knowledge_base=kb)
        self.inheritance_engine = inheritance_engine

    def parse_smali_types(self, smali_args: str) -> List[str]:
        """
        Parses a Smali argument string into a list of Java types.
        Handles nested arrays and objects correctly.
        """
        # Regex to match:
        # 1. Any number of '[' followed by a primitive char
        # 2. Any number of '[' followed by 'L'...';'
        # 3. A single primitive char
        # 4. 'L'...';'
        pattern = re.compile(r"(\[+[ZBSCIJFDV]|\[+L[^;]+;|[ZBSCIJFDV]|L[^;]+;)")
        matches = pattern.findall(smali_args)
        
        java_types = []
        for m in matches:
            array_depth = m.count("[")
            inner_type = m.lstrip("[")
            
            if inner_type.startswith("L"):
                # Object type: Lpkg/Name; -> pkg.Name
                final_type = inner_type[1:-1].replace("/", ".")
            else:
                # Primitive type
                final_type = self.PRIMITIVE_MAP.get(inner_type, inner_type)
            
            # Re-attach array notation if needed
            # NOTE: Frida's .overload() uses '[B' or '[Ljava.lang.String;' format for arrays, 
            # OR it can use 'byte[]' depending on version, but the raw descriptor is usually most precise.
            if array_depth > 0:
                # We build the descriptor for .overload()
                # For objects it needs the 'L...;' part preserved if using descriptors
                if inner_type.startswith("L"):
                    final_type = "[" * array_depth + inner_type.replace("/", ".")
                else:
                    final_type = "[" * array_depth + inner_type
            
            java_types.append(final_type)
            
        return java_types

    def generate_script(self, signature: str, method_body: Optional[List[str]] = None) -> Optional[str]:
        """
        Generates a smart Frida script with argument and return value logging.
        Uses Data Flow Analysis (DFA) to suggest precise argument names.
        """
        if "->" not in signature:
            logger.error(f"Invalid signature for Frida: {signature}")
            return None

        class_part, method_part = signature.split("->", 1)
        # Parse class: Lpkg/Name; -> pkg.Name
        java_class = class_part[1:-1].replace("/", ".")
        
        # Parse method name and arguments
        method_name = method_part.split("(")[0]
        # Constructor fix: <init> -> $init
        frida_method_name = "$init" if method_name == "<init>" else method_name
        
        args_raw = method_part.split("(")[1].split(")")[0]
        java_args = self.parse_smali_types(args_raw)
        
        # Track argument usage if body is provided
        arg_names = [f"arg{i}" for i in range(len(java_args))]
        inferred_usages = {}
        
        if method_body:
            # Analyze register flow: p0 is 'this' if non-static, p1 is arg0...
            dfa_results = self.tracker.analyze_method(method_body)
            
            # Match pX to argX: 
            # Non-static: p1 -> arg0, p2 -> arg1...
            # Static: p0 -> arg0, p1 -> arg1...
            # Bug #13 fix: Scan entire method body for static detection
            # (previously only scanned first 20 lines which could miss it)
            is_static = any(".method static" in l for l in method_body)
            base_p = 0 if is_static else 1
            
            for i in range(len(java_args)):
                p_reg = f"p{i + base_p}"
                type_name = java_args[i] # This is either pkg.Name or descriptor for arrays
                
                # Check Inheritance for better name
                if self.inheritance_engine:
                    smali_type = f"L{type_name.replace('.', '/')};"
                    type_label = self.inheritance_engine.identify_type(smali_type)
                    if type_label:
                        arg_names[i] = f"{type_label.lower()}_{i}"

                # Overlay DFA results if available (they are more specific to usage)
                if p_reg in dfa_results:
                    usages = dfa_results[p_reg]
                    suggested = self.tracker.suggest_name(p_reg, usages)
                    if suggested != p_reg:
                        arg_names[i] = f"{suggested}_{i}" # Adiciona index para evitar duplicatas
                        inferred_usages[i] = usages

        # Build the script
        script_lines = [
            "/*",
            " * Generated by Scout Frida Engine",
            f" * Target: {signature}",
            " */",
            "",
            "Java.perform(function() {",
            f"    var targetClass = Java.use('{java_class}');",
            f"    var targetMethod = targetClass.{frida_method_name};",
            ""
        ]
        
        # Handle overloads
        overload_args = ", ".join([f"'{a}'" for a in java_args])
        impl_args = ", ".join(arg_names)
        
        script_lines.append(f"    targetMethod.overload({overload_args}).implementation = function({impl_args}) {{")
        script_lines.append(f"        console.log('\\n[HIT] {signature}');")
        
        # Log arguments with inferred meanings
        for i in range(len(java_args)):
            name = arg_names[i]
            type_str = java_args[i]
            script_lines.append(f"        console.log('    |-- {name} ({type_str}): ' + {name});")
            if i in inferred_usages:
                major_usage = inferred_usages[i][0].split("(")[0]
                script_lines.append(f"        // Inferred from usage in {major_usage}")

        script_lines.append(f"        var result = this.{method_name}.apply(this, arguments);")
        
        # Check if it has a return value (not 'V')
        return_raw = method_part.split(")")[-1]
        if return_raw != "V":
            script_lines.append("        console.log('    |-- return: ' + result);")
            
        script_lines.append(f"        return result;")
        script_lines.append("    };")
        script_lines.append("});")
        
        return "\n".join(script_lines)

    def write_hook(self, signature: str, method_body: Optional[List[str]] = None, output_path: str = "scout_hook.js"):
        script = self.generate_script(signature, method_body)
        if script:
            Path(output_path).write_text(script, encoding="utf-8")
            logger.info(f"[FRIDA] Hook written to {output_path}")
            return True
        return False

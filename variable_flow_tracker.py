#!/usr/bin/env python3
"""
VariableFlowTracker - Análise inter-procedural de variável específica.

Rastreia o fluxo de uma variável através de múltiplos métodos,
campos e ramificações, com suporte a profundidade configurável.

Uso:
    from variable_flow_tracker import VariableFlowTracker
    tracker = VariableFlowTracker(class_index, file_cache, inheritance_engine, xref_engine, max_depth=10)
    result = tracker.track_variable("Lcom/example/Class;", "methodName", "p2")

Funcionalidades:
    - Tracking recursivo de variáveis através de métodos
    - Suporte a campos (field read/write)
    - Rastreamento em ramificações (if, switch)
    - Profundidade configurável
    - Integração com XREF e Inheritance engines

Exemplo de output:
    {
        "method": "Lcom/example/Login;->authenticate(Ljava/lang/String;)V",
        "variable": "p2",
        "depth": 3,
        "flows": [...],
        "usage_points": [...],
        "limite_atingido": false
    }
"""

import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path


class OperationType(Enum):
    """Tipos de operação que podem ocorrer com uma variável."""
    WRITE = "WRITE"
    READ = "READ"
    PASS = "PASS"
    RETURN = "RETURN"
    TRANSFORM = "TRANSFORM"
    FIELD_WRITE = "FIELD_WRITE"
    FIELD_READ = "FIELD_READ"


@dataclass
class UsagePoint:
    """Ponto de uso de uma variável no código."""
    line_number: int
    instruction: str
    operation: OperationType
    state: str
    variable_state_after: str = ""
    calls: Optional[Dict] = None
    field: Optional[str] = None
    bifurcation: Optional[str] = None


@dataclass
class MethodFlow:
    """Fluxo de uma variável em um método específico."""
    depth: int
    method: str
    usage: List[Dict[str, Any]] = field(default_factory=list)
    bifurcation_points: List[Dict[str, Any]] = field(default_factory=list)
    limite_atingido: bool = False
    retorno_verificado: bool = False
    field_written: Optional[str] = None
    field_consumers: List[str] = field(default_factory=list)


class VariableFlowTracker:
    """
    Tracker para análise de fluxo de variáveis em código Smali.
    
    Suporta:
    - Rastreamento intra-método de variáveis
    - Análise recursiva de métodos chamados
    - Tracking de campos (fields) e seus consumidores
    - Detecção de bifurcações (branching)
    - Profundidade configurável
    """
    
    def __init__(
        self,
        class_index: Dict[str, List[Path]],
        file_cache: Any,
        inheritance_engine: Any = None,
        xref_engine: Any = None,
        max_depth: int = 10
    ):
        self.class_index = class_index
        self.file_cache = file_cache
        self.inheritance_engine = inheritance_engine
        self.xref_engine = xref_engine
        self.max_depth = max_depth
        
        self._visited: Set[Tuple[str, str, str]] = set()
        
        self.RE_CONST_STRING = re.compile(r'const-string(?:/jumbo)?\s+([vp0-9]+),\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
        self.RE_CONST_INT = re.compile(r'const(?:/4|/16|/high16)?\s+([vp0-9]+),\s+(-?0x[a-fA-F0-9]+|-?\d+)')
        self.RE_INVOKE = re.compile(r"invoke-(\w+)\s+({[^}]*}|([vp0-9]+)\s*\.\.\s*([vp0-9]+)),\s*(L[^;]+;->[^\s]+)")
        self.RE_FIELD = re.compile(r'(i|s)(get|put)(?:-object|-wide|-short|-byte|-char|-int)?(?:-object)?\s+([vp0-9]+),\s*(?:([vp0-9]+|p0|L[^;]+;),)?\s*(L[^;]+;->[^\s]+)')
        self.RE_IF = re.compile(r'if-(\w+)\s+([vp0-9]+),\s*([vp0-9]+)?,?\s*([:[^\s]+)')
        self.RE_MOVE = re.compile(r'move(?:-object|-wide|-int|-float|-result)?\s+([vp0-9]+),\s+([vp0-9]+)')
        self.RE_MOVE_RESULT = re.compile(r'move-result(?:-object|-wide)?\s+([vp0-9]+)')
        self.RE_RETURN = re.compile(r'return(?:-void|-object|-wide|-int|-float)?\s+([vp0-9]+)?')
        self.RE_LABEL = re.compile(r'^(\s*):(\w+)\s*$')
        
        self.RE_VAR_PATTERN = re.compile(r'\b([vp][0-9]+)\b')
        self.RE_RANGE = re.compile(r'([vp])([0-9]+)\s*\.\.\s*[vp]([0-9]+)')

    def track_variable(
        self,
        class_sig: str,
        method_sig: str,
        variable: str,
        initial_context: str = "param"
    ) -> Dict[str, Any]:
        """
        Analisa o fluxo de uma variável específica.
        
        Args:
            class_sig: Assinatura da classe (ex: Lcom/example/Login;)
            method_sig: Assinatura do método (ex: doLogin(Ljava/lang/String;)Z)
            variable: Variável a rastrear (ex: p2, v0)
            initial_context: Contexto inicial (param, return, field, temp)
            
        Returns:
            Dicionário com o relatório de análise
        """
        self._visited.clear()
        
        query = {
            "class": class_sig,
            "method": method_sig,
            "variable": variable,
            "depth_limit": self.max_depth
        }
        
        flow = self._track_recursive(class_sig, method_sig, variable, 0, initial_context)
        
        summary = self._build_summary(flow)
        
        return {
            "query": query,
            "flow": flow,
            "summary": summary
        }

    def _track_recursive(
        self,
        class_sig: str,
        method_sig: str,
        variable: str,
        depth: int,
        context: str
    ) -> List[Dict[str, Any]]:
        """Análise recursiva do fluxo de variável."""
        full_method = f"{class_sig}->{method_sig}"
        cache_key = (class_sig, method_sig, variable)
        
        if cache_key in self._visited:
            return []
        
        self._visited.add(cache_key)
        
        method_body = self._load_method_body(class_sig, method_sig)
        if not method_body:
            return []
        
        method_flow = self._analyze_method_body(
            method_body, full_method, variable, depth
        )
        
        results = [method_flow]
        
        if depth >= self.max_depth:
            method_flow["limite_atingido"] = True
            method_flow["retorno_verificado"] = True
            return results
        
        for usage in method_flow.get("usage", []):
            if usage.get("operation") == "PASS":
                call_info = usage.get("calls", {})
                next_method = call_info.get("method")
                if next_method:
                    parts = next_method.split("->")
                    if not parts or len(parts) < 2:
                        continue
                    next_class = parts[0]
                    if not next_class.endswith(";"):
                        next_class += ";"
                    next_method_name = parts[1]
                    
                    param_idx = call_info.get("arg_index", 0)
                    next_variable = f"p{param_idx}"
                    
                    if next_class in self.class_index and next_method_name:
                        next_results = self._track_recursive(
                            next_class, next_method_name, next_variable, depth + 1, "param"
                        )
                        results.extend(next_results)
            
            elif usage.get("operation") == "FIELD_WRITE":
                field_sig = usage.get("field")
                if field_sig and self.xref_engine:
                    consumers = self._get_field_consumers(field_sig)
                    method_flow["field_consumers"].extend(consumers)
                    
                    for consumer in consumers:
                        consumer_parts = consumer.split("->")
                        if not consumer_parts or len(consumer_parts) < 2:
                            continue
                        consumer_class = consumer_parts[0] + ";"
                        consumer_method = consumer_parts[1]
                        consumer_results = self._track_recursive(
                            consumer_class, consumer_method, variable, depth + 1, "field"
                        )
                        results.extend(consumer_results)
            
            elif usage.get("operation") in ("TRANSFORM", "RETURN"):
                pass
        
        return results

    def _load_method_body(self, class_sig: str, method_sig: str) -> Optional[List[str]]:
        """Carrega o corpo de um método a partir do class_index."""
        if class_sig not in self.class_index:
            return None
        
        paths = self.class_index[class_sig]
        if not paths:
            return None
        
        path = paths[-1]
        
        content = self.file_cache.get(path)
        if not content:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except Exception:
                return None
        
        lines = content.splitlines()
        
        in_method = False
        method_lines = []
        
        method_name = method_sig.split("(")[0] if "(" in method_sig else method_sig
        method_pattern = re.compile(r'\.method\s+.*?' + re.escape(method_name))
        
        for i, line in enumerate(lines):
            if method_pattern.match(line.strip()):
                in_method = True
                method_lines.append(line)
                continue
            
            if in_method:
                if line.strip().startswith(".end method"):
                    method_lines.append(line)
                    break
                method_lines.append(line)
        
        return method_lines if method_lines else None

    def _analyze_method_body(
        self,
        method_body: List[str],
        method_sig: str,
        variable: str,
        depth: int
    ) -> Dict[str, Any]:
        """Analisa o corpo de um método para encontrar usos da variável."""
        usage_points = []
        bifurcation_points = []
        
        labels = {}
        
        line_num = 0
        i = 0
        while i < len(method_body):
            line = method_body[i].strip()
            line_num = i
            
            if not line or line.startswith((".", "#")):
                i += 1
                continue
            
            label_match = self.RE_LABEL.match(line)
            if label_match:
                labels[label_match.group(2)] = line_num
                i += 1
                continue
            
            extracted_vars = self._extract_all_variables(line)
            
            if variable not in extracted_vars and variable not in line:
                i += 1
                continue
            
            operation = self._classify_operation(line, variable)
            
            if operation == OperationType.READ and self.RE_IF.match(line):
                if_match = self.RE_IF.match(line)
                if if_match:
                    cond_type = if_match.group(1)
                    target_label = if_match.group(4)
                    if target_label.startswith(":"):
                        target_label = target_label[1:]
                    
                    existing = [b for b in bifurcation_points if b.get("label") == target_label]
                    if not existing:
                        bifurcation_points.append({
                            "label": target_label,
                            "condition": f"if-{cond_type}",
                            "line": line_num,
                            "variable": variable
                        })
            
            state, state_after = self._generate_state(line, operation, variable)
            
            usage = {
                "line": line_num,
                "instruction": line,
                "operation": operation.value,
                "state": state,
                "variable_state_after": state_after
            }
            
            if operation == OperationType.PASS:
                target = self._extract_invoke_target(line)
                param_idx = self._get_parameter_index(line, variable)
                usage["calls"] = {
                    "method": target,
                    "arg_index": param_idx,
                    "analyze_recursively": True
                }
            
            elif operation == OperationType.FIELD_WRITE:
                field_sig = self._extract_field_signature(line)
                usage["field"] = field_sig
            
            elif operation == OperationType.TRANSFORM:
                target = self._extract_invoke_target(line)
                usage["transform_target"] = target
            
            usage_points.append(usage)
            
            i += 1
        
        return {
            "depth": depth,
            "method": method_sig,
            "usage": usage_points,
            "bifurcation_points": bifurcation_points,
            "limite_atingido": False,
            "retorno_verificado": False
        }

    def _extract_all_variables(self, line: str) -> List[str]:
        """Extrai todas as variáveis de uma linha."""
        vars_found = set()
        
        for match in self.RE_VAR_PATTERN.finditer(line):
            vars_found.add(match.group(1))
        
        return list(vars_found)

    def _classify_operation(self, line: str, variable: str = None) -> OperationType:
        """Classifica o tipo de operação baseada na instrução."""
        if line.startswith("const"):
            return OperationType.WRITE
        
        if line.startswith("move-result"):
            return OperationType.TRANSFORM
        
        if line.startswith("move ") and not line.startswith("move-result"):
            return OperationType.WRITE
        
        if "invoke-" in line and "->" in line:
            if variable:
                if variable in line:
                    return OperationType.PASS
            else:
                target = self._extract_invoke_target(line)
                if target:
                    return_type = target.split(")")[-1] if ")" in target else "V"
                    if return_type != "V":
                        return OperationType.TRANSFORM
                    return OperationType.PASS
        
        if line.startswith("if-"):
            return OperationType.READ
        
        if line.startswith("return") and "return-void" not in line:
            return OperationType.RETURN
        
        field_match = self.RE_FIELD.match(line)
        if field_match:
            op_type = field_match.group(2)
            if op_type in ("put", "sput"):
                return OperationType.FIELD_WRITE
            else:
                return OperationType.FIELD_READ
        
        return OperationType.READ

    def _extract_register_list(self, line: str) -> List[str]:
        """Extrai lista de registradores de uma instrução."""
        brace_start = line.find("{")
        brace_end = line.find("}")
        
        if brace_start == -1 or brace_end == -1:
            return []
        
        regs_str = line[brace_start + 1:brace_end]
        
        if "..." in regs_str:
            range_match = self.RE_RANGE.search(regs_str)
            if range_match:
                prefix = range_match.group(1)
                start = int(range_match.group(2))
                end = int(range_match.group(3))
                return [f"{prefix}{i}" for i in range(start, end + 1)]
        
        return [r.strip() for r in regs_str.split(",") if r.strip()]

    def _extract_invoke_target(self, line: str) -> Optional[str]:
        """Extrai o método alvo de um invoke."""
        match = self.RE_INVOKE.search(line)
        if match:
            return match.group(5)
        return None

    def _extract_field_signature(self, line: str) -> Optional[str]:
        """Extrai assinatura de campo de iput/iget."""
        match = self.RE_FIELD.match(line)
        if match:
            return match.group(5)
        return None

    def _get_parameter_index(self, line: str, variable: str) -> int:
        """Retorna o índice do parâmetro no invoke."""
        regs = self._extract_register_list(line)
        try:
            return regs.index(variable)
        except ValueError:
            return -1

    def _generate_state(self, line: str, operation: OperationType, variable: str) -> Tuple[str, str]:
        """Gera descrição do estado da variável."""
        if operation == OperationType.WRITE:
            const_match = self.RE_CONST_STRING.match(line)
            if const_match:
                val = const_match.group(2)
                return f"{variable} = constant '{val}'", "constant_value"
            
            move_match = self.RE_MOVE.match(line)
            if move_match:
                src = move_match.group(2)
                return f"{variable} = {src}", "copied_value"
            
            return f"{variable} assigned", "written"
        
        elif operation == OperationType.READ:
            if_match = self.RE_IF.match(line)
            if if_match:
                return f"{variable} compared in condition", "compared"
            return f"{variable} read", "read"
        
        elif operation == OperationType.PASS:
            target = self._extract_invoke_target(line)
            idx = self._get_parameter_index(line, variable)
            return f"{variable} passed as arg {idx} to {target}", "passed_to_method"
        
        elif operation == OperationType.TRANSFORM:
            target = self._extract_invoke_target(line)
            return f"{variable} transformed by {target}", "transformed_value"
        
        elif operation == OperationType.RETURN:
            return f"{variable} returned to caller", "returned"
        
        elif operation == OperationType.FIELD_WRITE:
            field_sig = self._extract_field_signature(line)
            return f"{variable} stored in field {field_sig}", "field_value"
        
        elif operation == OperationType.FIELD_READ:
            field_sig = self._extract_field_signature(line)
            return f"{variable} read from field {field_sig}", "field_value"
        
        return f"{variable} referenced", "unknown"

    def _get_field_consumers(self, field_sig: str) -> List[str]:
        """Retorna métodos que lêem um campo."""
        if not self.xref_engine:
            return []
        
        consumers = self.xref_engine.field_accesses.get(field_sig, set())
        return list(consumers)

    def _parse_signature(self, sig: str) -> Tuple[str, str, List[str], str]:
        """Parsa assinatura de método."""
        if "->" not in sig:
            return sig, "", [], ""
        
        class_part, method_part = sig.split("->", 1)
        
        param_start = method_part.find("(")
        param_end = method_part.find(")")
        
        method_name = method_part[:param_start]
        
        params_str = method_part[param_start + 1:param_end]
        params = self._parse_params(params_str)
        
        return_type = method_part[param_end + 1:]
        
        return class_part + ";" if not class_part.endswith(";") else class_part, method_name, params, return_type

    def _parse_params(self, params_str: str) -> List[str]:
        """Parsa parâmetros de método."""
        if not params_str:
            return []
        
        params = []
        i = 0
        while i < len(params_str):
            if params_str[i] == "L":
                semi = params_str.find(";", i)
                params.append(params_str[i:semi + 1])
                i = semi + 1
            elif params_str[i] == "[":
                arr_start = i
                while i < len(params_str) and params_str[i] == "[":
                    i += 1
                if i < len(params_str):
                    if params_str[i] == "L":
                        semi = params_str.find(";", i)
                        params.append(params_str[arr_start:semi + 1])
                        i = semi + 1
                    else:
                        params.append(params_str[arr_start:i + 1])
                        i += 1
            elif params_str[i] in "ZBSCIJFDV":
                params.append(params_str[i])
                i += 1
            else:
                i += 1
        
        return params

    def _build_summary(self, flow: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Constrói resumo da análise."""
        total_methods = len(set(f.get("method", "") for f in flow))
        
        all_usages = []
        for f in flow:
            all_usages.extend(f.get("usage", []))
        
        modifications = [
            u for u in all_usages 
            if u.get("operation") in ("WRITE", "TRANSFORM", "FIELD_WRITE")
        ]
        
        lifecycle = []
        if "constant_value" in [u.get("variable_state_after") for u in all_usages]:
            lifecycle.append("constant_value")
        if "passed_to_method" in [u.get("variable_state_after") for u in all_usages]:
            lifecycle.append("passed_to_method")
        if "transformed_value" in [u.get("variable_state_after") for u in all_usages]:
            lifecycle.append("transformed_value")
        if "field_value" in [u.get("variable_state_after") for u in all_usages]:
            lifecycle.append("field_value")
        if "returned" in [u.get("variable_state_after") for u in all_usages]:
            lifecycle.append("returned")
        
        terminated = not any(u.get("operation") in ("PASS", "FIELD_WRITE", "RETURN") for u in all_usages)
        
        return {
            "total_methods_analyzed": total_methods,
            "total_usage_points": len(all_usages),
            "variable_modifications": modifications,
            "lifecycle": lifecycle,
            "flow_terminated": terminated,
            "termination_reason": "no_more_references" if terminated else "pending"
        }


def intern_sig(s: str) -> str:
    """Interns a string to save memory for repeated signatures."""
    return sys.intern(s) if isinstance(s, str) else s
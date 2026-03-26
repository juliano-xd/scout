#!/usr/bin/env python3
"""
ObfuscationDetector - Detecção de técnicas de obfuscação em código Smali Android.

Detecta:
- Reflection dinâmica (Class.forName, Method.invoke, etc)
- String deobfuscation (Base64, XOR, crypto custom)
- Código nativo (System.load, JNI, etc)

Uso:
    from obfuscation_engine import ObfuscationDetector
    detector = ObfuscationDetector(class_index, file_cache)
    result = detector.analyze_class("Lcom/example/Class;")

Exemplo de output:
    {
        "reflection_findings": [...],
        "string_decryptions": [...],
        "native_calls": [...],
        "risk_level": "high|medium|low",
        "recommendations": [...]
    }

支持的检测类型:
    - Reflection: Class.forName, Method.invoke, Constructor.newInstance
    - Strings: Base64 decode, XOR, custom crypto, string concat
    - Native: System.load, System.loadLibrary, Runtime.load
"""

import re
import sys
import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


class ReflectionType(Enum):
    """Tipos de chamada reflection."""
    CLASS_FORNAME = "class_forName"
    METHOD_INVOKE = "method_invoke"
    CONSTRUCTOR_NEWINSTANCE = "constructor_newInstance"
    CLASSLOADER_LOAD = "classloader_load"


class DecryptionType(Enum):
    """Tipos de padrões de descriptografia."""
    BASE64 = "base64"
    CUSTOM_CRYPTO = "custom_crypto"
    XOR = "xor"
    STRING_CONCAT = "string_concat"
    BYTE_ARRAY = "byte_array"


class NativeType(Enum):
    """Tipos de chamadas nativas."""
    SYSTEM_LOAD = "system_load"
    SYSTEM_LOAD_LIBRARY = "loadLibrary"
    RUNTIME_LOAD = "runtime_load"
    JNI = "jni"


@dataclass
class ReflectionFinding:
    """Encontrado Reflection call."""
    method: str
    reflection_type: ReflectionType
    target: str = ""
    dynamic_execution: List[str] = field(default_factory=list)
    line: int = 0
    is_system_class: bool = False


@dataclass
class DecryptionFinding:
    """Encontrado padrão de descriptografia."""
    method: str
    pattern_type: DecryptionType
    input_source: str = ""
    output_var: str = ""
    decoded_value: Optional[str] = None
    line: int = 0


@dataclass
class NativeFinding:
    """Encontrado uso de código nativo."""
    method: str
    native_type: NativeType
    library: str = ""
    function: Optional[str] = None
    line: int = 0


class ObfuscationDetector:
    """
    Detector de técnicas de obfuscação em código Smali.
    
    Suporta:
    - Detecção de reflection dinâmica
    - Detecção de descriptografia de strings
    - Detecção de código nativo
    - Tracking dinâmico de alvos reflection
    """
    
    def __init__(
        self,
        class_index: Dict[str, List[Path]],
        file_cache: Any,
        max_depth: int = 3
    ):
        self.class_index = class_index
        self.file_cache = file_cache
        self.max_depth = max_depth
        
        self.SYSTEM_PREFIXES = ("Ljava/", "Ljavax/", "Landroid/", "Lcom/android/", "Ldalvik/", "Lkotlin/")
        
        self.REFLECTION_PATTERNS = [
            (re.compile(r'invoke-static\s+{[^}]*},\s*Ljava/lang/Class;->forName\(Ljava/lang/String;\)Ljava/lang/Class;'), ReflectionType.CLASS_FORNAME),
            (re.compile(r'invoke-virtual\s+{[^}]*},\s*Ljava/lang/reflect/Method;->invoke\(Ljava/lang/Object;\[Ljava/lang/Object;\)Ljava/lang/Object;'), ReflectionType.METHOD_INVOKE),
            (re.compile(r'invoke-virtual\s+{[^}]*},\s*Ljava/lang/reflect/Constructor;->newInstance\(\[Ljava/lang/Object;\)Ljava/lang/Object;'), ReflectionType.CONSTRUCTOR_NEWINSTANCE),
            (re.compile(r'invoke-virtual\s+{[^}]*},\s*Ljava/lang/ClassLoader;->loadClass\(Ljava/lang/String;\)Ljava/lang/Class;'), ReflectionType.CLASSLOADER_LOAD),
        ]
        
        self.DECRYPTION_PATTERNS = [
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Landroid/util/Base64;->decode'), DecryptionType.BASE64),
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Landroid/util/Base64;->decodeString'), DecryptionType.BASE64),
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Ljavax/crypto/Cipher;->getInstance'), DecryptionType.CUSTOM_CRYPTO),
            (re.compile(r'invoke-virtual\s+{[^}]*},\s*Ljavax/crypto/Cipher;->doFinal'), DecryptionType.CUSTOM_CRYPTO),
            (re.compile(r'xor-(?:int|long|short)\s+v\d+,\s*v\d+,\s*v\d+'), DecryptionType.XOR),
            (re.compile(r'invoke-static\s+{[^}]*},\s*Ljava/lang/String;->concat'), DecryptionType.STRING_CONCAT),
            (re.compile(r'new-array\s+\w+,\s*\w+,\s*\[B'), DecryptionType.BYTE_ARRAY),
        ]
        
        self.NATIVE_PATTERNS = [
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Ljava/lang/System;->load\(Ljava/lang/String;\)V'), NativeType.SYSTEM_LOAD),
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V'), NativeType.SYSTEM_LOAD_LIBRARY),
            (re.compile(r'invoke-static\s+{([^}]*)},\s*Ljava/lang/Runtime;->load\(Ljava/lang/String;\)V'), NativeType.RUNTIME_LOAD),
            (re.compile(r'RegisterNatives'), NativeType.JNI),
        ]
        
        self._visited_reflection: Set[str] = set()

    def detect_selected(self, types: List[str]) -> Dict[str, Any]:
        """Detecta obfuscação dos tipos selecionados."""
        result = {}
        
        if "reflection" in types or "all" in types:
            result["reflection"] = self.detect_reflection()
        
        if "strings" in types or "all" in types:
            result["strings"] = self.detect_string_decryption()
        
        if "native" in types or "all" in types:
            result["native"] = self.detect_native_code()
        
        return self._build_report(result)

    def detect_reflection(self) -> List[ReflectionFinding]:
        """Detecta chamadas reflection no código."""
        findings = []
        
        for class_sig, paths in self.class_index.items():
            if class_sig.startswith(self.SYSTEM_PREFIXES):
                continue
            
            if not paths:
                continue
            
            path = paths[-1]
            content = self._read_file(path)
            if not content:
                continue
            
            lines = content.splitlines()
            
            for pattern, ref_type in self.REFLECTION_PATTERNS:
                for i, line in enumerate(lines):
                    if pattern.search(line):
                        target = self._extract_reflection_target(line, ref_type, lines, i)
                        target_smali = f"L{target.replace('.', '/')};"
                        is_system = target_smali.startswith(self.SYSTEM_PREFIXES) if target else False
                        
                        dynamic_execution = []
                        if not is_system and target:
                            dynamic_execution = self._track_dynamic_execution(target)
                        
                        findings.append(ReflectionFinding(
                            method=class_sig,
                            reflection_type=ref_type,
                            target=target,
                            dynamic_execution=dynamic_execution,
                            line=i + 1,
                            is_system_class=is_system
                        ))
        
        return findings

    def _extract_reflection_target(self, line: str, ref_type: ReflectionType, context_lines: List[str] = None, current_idx: int = 0) -> str:
        """Extrai o alvo de uma chamada reflection."""
        const_match = re.search(r'const-string\s+(\w+),\s*"([^"]+)"', line)
        if const_match:
            return const_match.group(2)
        
        if context_lines:
            for i in range(max(0, current_idx - 5), current_idx):
                ctx_line = context_lines[i]
                const_match = re.search(r'const-string\s+(\w+),\s*"([^"]+)"', ctx_line)
                if const_match:
                    return const_match.group(2)
        
        return ""

    def _track_dynamic_execution(self, target: str) -> List[str]:
        """Rastreia a execução dinâmica de um alvo reflection."""
        if target in self._visited_reflection:
            return []
        
        self._visited_reflection.add(target)
        
        class_sig = f"L{target.replace('.', '/')};"
        
        if class_sig not in self.class_index:
            return []
        
        paths = self.class_index[class_sig]
        if not paths:
            return []
        
        path = paths[-1]
        content = self._read_file(path)
        if not content:
            return []
        
        methods = []
        method_pattern = re.compile(r'\.method\s+.*?\b(\w+)\([^)]*\)[^\s]+')
        
        for match in method_pattern.finditer(content):
            method_name = match.group(1)
            if method_name not in ("<init>", "<clinit>", "<class>"):
                methods.append(f"{class_sig}->{method_name}()V")
        
        return methods[:10]

    def detect_string_decryption(self) -> List[DecryptionFinding]:
        """Detecta padrões de descriptografia de strings."""
        findings = []
        
        for class_sig, paths in self.class_index.items():
            if not paths:
                continue
            
            path = paths[-1]
            content = self._read_file(path)
            if not content:
                continue
            
            lines = content.splitlines()
            
            for i, line in enumerate(lines):
                for pattern, dec_type in self.DECRYPTION_PATTERNS:
                    if pattern.search(line):
                        input_source, output_var = self._extract_decryption_context(line, dec_type, lines, i)
                        decoded_value = self._try_infer_decoded_value(input_source, dec_type)
                        
                        findings.append(DecryptionFinding(
                            method=class_sig,
                            pattern_type=dec_type,
                            input_source=input_source,
                            output_var=output_var,
                            decoded_value=decoded_value,
                            line=i + 1
                        ))
                        break
        
        return findings

    def _extract_decryption_context(self, line: str, dec_type: DecryptionType, lines: List[str], line_idx: int) -> tuple:
        """Extrai contexto de descriptografia (input/output)."""
        input_source = ""
        output_var = ""
        
        const_match = re.search(r'const-string\s+(\w+),\s*"([^"]+)"', line)
        if const_match:
            input_source = const_match.group(2)
            output_var = const_match.group(1)
        
        move_result = re.search(r'move-result-object\s+(\w+)', line)
        if move_result:
            output_var = move_result.group(1)
        
        return input_source, output_var

    def _try_infer_decoded_value(self, input_source: str, dec_type: DecryptionType) -> Optional[str]:
        """Tenta inferir o valor decodificado."""
        if not input_source or dec_type != DecryptionType.BASE64:
            return None
        
        try:
            decoded = base64.b64decode(input_source)
            if decoded and len(decoded) < 100:
                return decoded.decode('utf-8', errors='replace')
        except:
            pass
        
        return None

    def detect_native_code(self) -> List[NativeFinding]:
        """Detecta uso de código nativo."""
        findings = []
        
        for class_sig, paths in self.class_index.items():
            if not paths:
                continue
            
            path = paths[-1]
            content = self._read_file(path)
            if not content:
                continue
            
            lines = content.splitlines()
            
            for pattern, native_type in self.NATIVE_PATTERNS:
                for i, line in enumerate(lines):
                    if pattern.search(line):
                        library = self._extract_library_name(line)
                        
                        findings.append(NativeFinding(
                            method=class_sig,
                            native_type=native_type,
                            library=library,
                            line=i + 1
                        ))
        
        return findings

    def _extract_library_name(self, line: str) -> str:
        """Extrai o nome da biblioteca de uma chamada native."""
        const_match = re.search(r'const-string\s+(\w+),\s*"([^"]+)"', line)
        if const_match:
            return const_match.group(2)
        
        return ""

    def _read_file(self, path: Path) -> Optional[str]:
        """Lê o conteúdo de um arquivo com cache."""
        content = self.file_cache.get(path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except Exception:
                return None
        return content

    def _build_report(self, findings: Dict[str, List]) -> Dict[str, Any]:
        """Constrói o relatório final."""
        total_obf = sum(len(v) for v in findings.values())
        
        reflection_findings = findings.get("reflection", [])
        string_findings = findings.get("strings", [])
        native_findings = findings.get("native", [])
        
        high_risk = sum(1 for f in reflection_findings if f.target and not f.is_system_class)
        high_risk += sum(1 for f in string_findings if f.pattern_type in [DecryptionType.CUSTOM_CRYPTO, DecryptionType.XOR])
        high_risk += len(native_findings)
        
        return {
            "type": "obfuscation_analysis",
            "settings": {
                "detection_types": list(findings.keys()),
                "tracking_depth": self.max_depth
            },
            "findings": {
                "reflection": {
                    "total": len(reflection_findings),
                    "findings": [
                        {
                            "method": f.method,
                            "reflection_type": f.reflection_type.value,
                            "target": f.target,
                            "dynamic_execution": f.dynamic_execution,
                            "line": f.line,
                            "is_system_class": f.is_system_class
                        }
                        for f in reflection_findings
                    ]
                },
                "strings": {
                    "total": len(string_findings),
                    "findings": [
                        {
                            "method": f.method,
                            "pattern_type": f.pattern_type.value,
                            "input": f.input_source,
                            "output": f.output_var,
                            "decoded_hint": f.decoded_value,
                            "line": f.line
                        }
                        for f in string_findings
                    ]
                },
                "native": {
                    "total": len(native_findings),
                    "findings": [
                        {
                            "method": f.method,
                            "native_type": f.native_type.value,
                            "library": f.library,
                            "line": f.line
                        }
                        for f in native_findings
                    ]
                }
            },
            "summary": {
                "total_obfuscation_techniques": total_obf,
                "high_risk": high_risk,
                "medium_risk": len(reflection_findings) - high_risk + len(string_findings),
                "low_risk": len(native_findings)
            }
        }


def intern_sig(s: str) -> str:
    """Interns a string to save memory for repeated signatures."""
    return sys.intern(s) if isinstance(s, str) else s
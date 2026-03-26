#!/usr/bin/env python3
"""
AdvancedTrackingEngine - Módulo de análise profunda de código Smali.

Funcionalidades:
    - Taint analysis avançado com sources/sinks estendidos
    - Data Leak Detection (detecção de exfiltração de dados)
    - Crypto Analysis (detecção de crypto operations)
    - Sensitive Data Tracking (credenciais, PII, device info)
    - Network Exfiltration Detection
    - URL/Parameter Extraction Detection
    - Method Chaining Detection (builder patterns)
    - Cross-method Data Flow Analysis
    - Risk Assessment com recomendações

Uso:
    from advanced_tracking_engine import AdvancedTrackingEngine
    engine = AdvancedTrackingEngine(class_index, file_cache)
    result = engine.analyze_class("Lcom/example/Class;")

Exemplo de output (JSON):
    {
        "summary": {
            "total_sources": 5,
            "total_sinks": 3,
            "total_flows": 2,
            "risk_level": "high",
            "recommendations": [...]
        },
        "sources": [...],
        "sinks": [...],
        "data_flows": [...]
    }

Fontes detectadas:
    - Credentials: passwords, tokens, API keys
    - Device Info: IMEI, MAC, device ID
    - Location: GPS coordinates
    - PII: contacts, SMS
    - Biometric: fingerprint, face
    - Camera/Microphone access
    - URLs com parâmetros

Sinks detectadas:
    - Network: HTTP, OkHttp, HttpURLConnection
    - File: FileOutputStream, File write
    - SharedPreferences, Database
    - Log, Clipboard
    - Intent extras, Bundle
"""

import re
import base64
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path


class SensitiveType(Enum):
    """Tipos de dados sensíveis."""
    CREDENTIAL = "credential"
    PII = "pii"
    DEVICE_INFO = "device_info"
    LOCATION = "location"
    PAYMENT = "payment"
    AUTH_TOKEN = "auth_token"
    CUSTOM_KEY = "custom_key"
    BIOMETRIC = "biometric"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    URL = "url"


class SinkType(Enum):
    """Tipos de sinks (pontos de exfiltração)."""
    NETWORK = "network"
    FILE = "file"
    CRYPTO = "crypto"
    SHARED_PREFS = "shared_prefs"
    DATABASE = "database"
    CLIPBOARD = "clipboard"
    SMS = "sms"
    LOG = "log"
    SYSTEM = "system"
    INTENT = "intent"
    BUNDLE = "bundle"


@dataclass
class TaintSource:
    """Fonte de dados sensíveis."""
    register: str
    source_type: SensitiveType
    value: str
    line: int
    method: str


@dataclass
class TaintSink:
    """Sink (ponto de exfiltração)."""
    register: str
    sink_type: SinkType
    target: str
    line: int
    method: str


@dataclass
class DataFlow:
    """Fluxo de dados detectado."""
    source: TaintSource
    sink: TaintSink
    path: List[str]
    risk_level: str  # high, medium, low


@dataclass
class CryptoOperation:
    """Operação criptográfica detectada."""
    method: str
    operation_type: str  # encrypt, decrypt, hash, generate_key
    algorithm: str
    key_source: str
    line: int


class AdvancedTrackingEngine:
    """
    Engine de tracking avançado com análise profunda.
    """
    
    def __init__(self, class_index: Dict[str, List[Path]], file_cache: Any):
        self.class_index = class_index
        self.file_cache = file_cache
        
        self.SENSITIVE_SOURCES = {
            "Landroid/telephony/TelephonyManager;->getDeviceId": SensitiveType.DEVICE_INFO,
            "Landroid/telephony/TelephonyManager;->getSubscriberId": SensitiveType.DEVICE_INFO,
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber": SensitiveType.DEVICE_INFO,
            "Landroid/telephony/TelephonyManager;->getImei": SensitiveType.DEVICE_INFO,
            "Landroid/net/wifi/WifiInfo;->getMacAddress": SensitiveType.DEVICE_INFO,
            "Landroid/location/LocationManager;->getLastKnownLocation": SensitiveType.LOCATION,
            "Landroid/location/Location;->getLatitude": SensitiveType.LOCATION,
            "Landroid/location/Location;->getLongitude": SensitiveType.LOCATION,
            "Landroid/content/ContentResolver;->query": SensitiveType.PII,
            "Landroid/provider/ContactsContract;->": SensitiveType.PII,
            "Landroid/provider/Telephony;->SMS": SensitiveType.PII,
            "Ljava/lang/String;->getBytes": SensitiveType.CREDENTIAL,
            "Landroid/util/Base64;->decode": SensitiveType.CUSTOM_KEY,
            "Landroid/preference/SharedPreferences;->getString": SensitiveType.CREDENTIAL,
            "Landroid/hardware/biometrics/BiometricPrompt;->authenticate": SensitiveType.BIOMETRIC,
            "Landroid/hardware/Camera;->open": SensitiveType.CAMERA,
            "Landroid/media/AudioRecord;->startRecording": SensitiveType.MICROPHONE,
        }
        
        self.SINKS = {
            "Ljava/net/URL;->openConnection": SinkType.NETWORK,
            "Ljava/net/HttpURLConnection;->connect": SinkType.NETWORK,
            "Lokhttp3/OkHttpClient;->newCall": SinkType.NETWORK,
            "Lokhttp3/Request;->.Builder": SinkType.NETWORK,
            "Lapache/http/client/HttpClient;->execute": SinkType.NETWORK,
            "Ljava/io/FileOutputStream;->write": SinkType.FILE,
            "Ljava/io/File;->write": SinkType.FILE,
            "Landroid/content/SharedPreferences;->edit": SinkType.SHARED_PREFS,
            "Landroid/content/SharedPreferences;->putString": SinkType.SHARED_PREFS,
            "Landroid/content/SharedPreferences$Editor;->putString": SinkType.SHARED_PREFS,
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL": SinkType.DATABASE,
            "Landroid/database/sqlite/SQLiteDatabase;->insert": SinkType.DATABASE,
            "Ljava/lang/ProcessBuilder;->command": SinkType.SYSTEM,
            "Ljava/lang/Runtime;->exec": SinkType.SYSTEM,
            "Landroid/util/Log;->": SinkType.LOG,
            "Ljava/io/PrintWriter;->write": SinkType.LOG,
            "Landroid/clipboard/ClipboardManager;->setText": SinkType.CLIPBOARD,
            "Landroid/content/Intent;->putExtra": SinkType.INTENT,
            "Landroid/os/Bundle;->putString": SinkType.BUNDLE,
            "Landroid/os/Bundle;->putInt": SinkType.BUNDLE,
        }
        
        self.CRYPTO_PATTERNS = {
            "Ljavax/crypto/Cipher;->getInstance": "cipher_init",
            "Ljavax/crypto/Cipher;->init": "cipher_init",
            "Ljavax/crypto/Cipher;->doFinal": "cipher_final",
            "Ljavax/crypto/spec/SecretKeySpec;-><init>": "key_gen",
            "Ljavax/crypto/spec/IvParameterSpec;-><init>": "iv_gen",
            "Ljava/security/MessageDigest;->getInstance": "hash_init",
            "Ljava/security/MessageDigest;->digest": "hash_final",
            "Ljava/security/KeyPairGenerator;->initialize": "keypair_init",
            "Ljava/security/KeyPairGenerator;->generateKeyPair": "keypair_gen",
        }
        
        self.SENSITIVE_STRINGS = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "private", "credential", "auth", "bearer", "authorization",
            "card", "cvv", "expire", "ssn", "social", "dob",
            "http://", "https://", "www."
        ]
    
    def analyze_class(self, class_sig: str) -> Dict[str, Any]:
        """Analisa uma classe completa para dados sensíveis."""
        if class_sig not in self.class_index:
            return {"error": "Class not found"}
        
        paths = self.class_index[class_sig]
        if not paths:
            return {"error": "No path found"}
        
        content = self._read_file(paths[-1])
        if not content:
            return {"error": "Could not read file"}
        
        lines = content.splitlines()
        
        sources = []
        sinks = []
        crypto_ops = []
        flows = []
        
        in_method = False
        current_method = ""
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            if line.startswith(".method"):
                in_method = True
                current_method = class_sig + "->" + line.split()[-1].split("(")[0]
            
            elif line.startswith(".end method"):
                in_method = False
            
            elif in_method:
                source = self._detect_source(line, current_method, i + 1)
                if source:
                    sources.append(source)
                
                sink = self._detect_sink(line, current_method, i + 1)
                if sink:
                    sinks.append(sink)
                
                crypto = self._detect_crypto(line, current_method, i + 1)
                if crypto:
                    crypto_ops.append(crypto)
        
        flows = self._match_flows(sources, sinks)
        
        return self._build_json_output(sources, sinks, flows, self._assess_risk(sources, sinks, flows))
    
    def _build_json_output(self, sources: List[TaintSource], sinks: List[TaintSink], flows: List[DataFlow], risk_assessment: Dict) -> Dict[str, Any]:
        """Constrói output JSON estruturado para consumo por IA."""
        return {
            "summary": {
                "total_sources": len(sources),
                "total_sinks": len(sinks),
                "total_flows": len(flows),
                "risk_level": risk_assessment.get("risk_level", "low"),
                "high_risk_count": risk_assessment.get("high_risk_count", 0),
                "medium_risk_count": risk_assessment.get("medium_risk_count", 0),
                "recommendations": risk_assessment.get("recommendations", [])
            },
            "sources": [self._source_to_dict(s) for s in sources],
            "sinks": [self._sink_to_dict(s) for s in sinks],
            "data_flows": [self._flow_to_dict(f) for f in flows]
        }
    
    def _detect_source(self, line: str, method: str, line_num: int) -> Optional[TaintSource]:
        """Detecta fontes de dados sensíveis."""
        if line.startswith("const-string"):
            match = re.search(r'const-string\s+(\w+),\s*"([^"]+)"', line)
            if match:
                reg, val = match.groups()
                val_lower = val.lower()
                if "http://" in val_lower or "https://" in val_lower or "www." in val_lower:
                    return TaintSource(
                        register=reg,
                        source_type=SensitiveType.URL,
                        value=val,
                        line=line_num,
                        method=method
                    )
                for sensitive in self.SENSITIVE_STRINGS:
                    if sensitive in val_lower:
                        return TaintSource(
                            register=reg,
                            source_type=SensitiveType.CREDENTIAL,
                            value=val,
                            line=line_num,
                            method=method
                        )
            return None
        
        if not line.startswith("invoke"):
            return None
        
        for pattern, sens_type in self.SENSITIVE_SOURCES.items():
            if pattern in line:
                return TaintSource(
                    register="",
                    source_type=sens_type,
                    value=pattern.split("->")[-1],
                    line=line_num,
                    method=method
                )
        
        return None
    
    def _detect_sink(self, line: str, method: str, line_num: int) -> Optional[TaintSink]:
        """Detecta sinks (pontos de exfiltração)."""
        if not line.startswith("invoke"):
            return None
        
        for pattern, sink_type in self.SINKS.items():
            if pattern in line:
                return TaintSink(
                    register="",
                    sink_type=sink_type,
                    target=line.split("->")[-1] if "->" in line else line,
                    line=line_num,
                    method=method
                )
        
        return None
    
    def _detect_crypto(self, line: str, method: str, line_num: int) -> Optional[CryptoOperation]:
        """Detecta operações criptográficas."""
        if not line.startswith("invoke"):
            return None
        
        for pattern, op_type in self.CRYPTO_PATTERNS.items():
            if pattern in line:
                algorithm = "unknown"
                if "Cipher" in line:
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        algorithm = match.group(1)
                elif "MessageDigest" in line:
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        algorithm = match.group(1)
                
                return CryptoOperation(
                    method=method,
                    operation_type=op_type,
                    algorithm=algorithm,
                    key_source=self._extract_key_source(line, line_num),
                    line=line_num
                )
        
        return None
    
    def _extract_key_source(self, line: str, line_num: int) -> str:
        """Extrai a origem da chave de uma operação crypto."""
        if "SecretKeySpec" in line:
            return "hardcoded"
        if "KeyStore" in line:
            return "keystore"
        if "KeyGenerator" in line:
            return "generated"
        return "unknown"
    
    def _detect_method_chain(self, lines: List[str], method: str) -> bool:
        """Detecta encadeamento de métodos (builder pattern, StringBuilder, etc.)."""
        chain_patterns = [
            "Ljava/lang/StringBuilder;->append",
            "Ljava/lang/StringBuilder;->toString",
            "Ljava/lang/StringBuffer;->append",
            "Ljava/lang/StringBuffer;->toString",
            "Ljava/lang/String;->concat",
            "Ljava/lang/String;->valueOf",
            "Lokhttp3/Request$Builder;->url",
            "Lokhttp3/Request$Builder;->post",
            "Lokhttp3/Request$Builder;->build",
            "Landroid/content/Intent;->putExtra",
            "Landroid/os/Bundle;->putString",
        ]
        
        for line in lines:
            for pattern in chain_patterns:
                if pattern in line:
                    return True
        return False
    
    def _match_flows(self, sources: List[TaintSource], sinks: List[TaintSink]) -> List[DataFlow]:
        """Associa sources a sinks para identificar fluxos de dados."""
        flows = []
        matched_sinks = set()
        
        for source in sources:
            for sink in sinks:
                if source.method == sink.method and id(sink) not in matched_sinks:
                    matched_sinks.add(id(sink))
                    flows.append(DataFlow(
                        source=source,
                        sink=sink,
                        path=[source.method],
                        risk_level="high" if source.source_type in [SensitiveType.CREDENTIAL, SensitiveType.AUTH_TOKEN] else "medium"
                    ))
                    break
        
        return flows
    
    def _match_flows_cross_method(self, sources: List[TaintSource], sinks: List[TaintSink], method_calls: Dict[str, List[str]]) -> List[DataFlow]:
        """Associa sources a sinks em métodos diferentes mas com relação de chamada."""
        flows = []
        
        for source in sources:
            for sink in sinks:
                if source.method == sink.method:
                    continue
                
                called_methods = method_calls.get(source.method, [])
                if sink.method in called_methods:
                    flows.append(DataFlow(
                        source=source,
                        sink=sink,
                        path=[source.method, sink.method],
                        risk_level="high" if source.source_type in [SensitiveType.CREDENTIAL, SensitiveType.AUTH_TOKEN] else "medium"
                    ))
        
        return flows
    
    def _assess_risk(self, sources: List[TaintSource], sinks: List[TaintSink], flows: List[DataFlow]) -> Dict:
        """Avalia o risco geral da classe."""
        high_risk_count = sum(1 for s in sources if s.source_type in [SensitiveType.CREDENTIAL, SensitiveType.AUTH_TOKEN])
        medium_risk_count = sum(1 for s in sources if s.source_type in [SensitiveType.DEVICE_INFO, SensitiveType.PII])
        
        risk_level = "low"
        if high_risk_count > 0:
            risk_level = "high"
        elif medium_risk_count > 0:
            risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "total_sources": len(sources),
            "total_sinks": len(sinks),
            "total_flows": len(flows),
            "recommendations": self._generate_recommendations(sources, sinks, flows)
        }
    
    def _generate_recommendations(self, sources: List[TaintSource], sinks: List[TaintSink], flows: List[DataFlow]) -> List[str]:
        """Gera recomendações de segurança."""
        recs = []
        
        if any(s.source_type == SensitiveType.CREDENTIAL for s in sources):
            recs.append("Credential hardcoded detected - review storage mechanism")
        
        if any(s.source_type == SensitiveType.DEVICE_INFO for s in sources):
            recs.append("Device identifier collected - ensure proper consent/permissions")
        
        if len(flows) > 0:
            recs.append(f"Data exfiltration risk: {len(flows)} potential flows detected")
        
        if any(s.sink_type == SinkType.NETWORK for s in sinks):
            recs.append("Network sink detected - verify data encryption in transit")
        
        if any(s.sink_type == SinkType.LOG for s in sinks):
            recs.append("Logging sink detected - ensure no sensitive data in logs")
        
        return recs
    
    def _read_file(self, path: Path) -> Optional[str]:
        """Lê o conteúdo de um arquivo."""
        content = self.file_cache.get(path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.file_cache.put(path, content)
            except:
                return None
        return content
    
    def _source_to_dict(self, source: TaintSource) -> Dict:
        return {
            "type": source.source_type.value,
            "value": source.value,
            "line": source.line,
            "method": source.method
        }
    
    def _sink_to_dict(self, sink: TaintSink) -> Dict:
        return {
            "type": sink.sink_type.value,
            "target": sink.target,
            "line": sink.line,
            "method": sink.method
        }
    
    def _crypto_to_dict(self, crypto: CryptoOperation) -> Dict:
        return {
            "operation": crypto.operation_type,
            "algorithm": crypto.algorithm,
            "key_source": crypto.key_source,
            "line": crypto.line,
            "method": crypto.method
        }
    
    def _flow_to_dict(self, flow: DataFlow) -> Dict:
        return {
            "source_type": flow.source.source_type.value,
            "sink_type": flow.sink.sink_type.value,
            "path": flow.path,
            "risk_level": flow.risk_level
        }


def intern_sig(s: str) -> str:
    """Interns a string to save memory."""
    import sys
    return sys.intern(s) if isinstance(s, str) else s
# Scout Forensic Toolkit

Scout is a technical framework for Android static analysis, security auditing, and bytecode instrumentation. It provides automated tools for inspecting Smali bytecode, reconstructing control flow, and performing data-flow analysis.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SmaliScout CLI                           │
│                  (smali_scout.py - 2730 lines)                 │
└─────────────────────┬───────────────────────────────────────────┘
                      │
      ┌───────────────┼───────────────┬───────────────┬───────────┐
      ▼               ▼               ▼               ▼           ▼
┌──────────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐
│   Tracking   │ │  CFG     │ │ Semantic  │ │ Inherit. │ │  Frida   │
│   Engine     │ │ Engine   │ │ Engine    │ │ Engine   │ │ Engine   │
│  (XREF+Taint)│ │ (CFG)    │ │(Translate)│ │(BFS)     │ │(Hooks)   │
└──────────────┘ └──────────┘ └───────────┘ └──────────┘ └──────────┘
      │               │               │               │           │
      └───────────────┼───────────────┼───────────────┼───────────┘
                      ▼               ▼               ▼
              ┌──────────────┐ ┌──────────┐ ┌──────────┐
              │ UI Engine    │ │Reasoning │ │Behavior  │
              │(UI Tracing)  │ │ Engine   │ │ Engine   │
              └──────────────┘ └──────────┘ └──────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
┌──────────────────┐ ┌────────────────────┐ ┌──────────────────┐
│VariableFlowTracker│ │ObfuscationDetector│ │AdvancedTracking  │
│ (Inter-procedural│ │ (Reflection/String│ │ (Sources/Sinks   │
│  Variable Track) │ │  Native Detection) │ │  Crypto Analysis)│
└──────────────────┘ └────────────────────┘ └──────────────────┘
                              │
                              ▼
              ┌────────────────────────────────┐
              │     ScoutKnowledge (SQLite)    │
              │   (Framework + DFA Hints)       │
              └────────────────────────────────┘
```

## Engine Specifications

### 1. TrackingEngine (`tracking_engine.py`)
- **XREFEngine**: Cross-reference indexing with pickle persistence
- **TaintEngine**: Register-based data flow analysis
- **Priority**: SOURCE > FIELD > CONST > SINK

### 2. CFGEngine (`cfg_engine.py`)
- Builds basic blocks from method bodies
- Handles exceptions, switches, branches
- Exports to DOT format

### 3. SemanticEngine (`semantic_engine.py`)
- Translates Smali to Python-like pseudocode
- Statement folding for readability
- Try-catch reconstruction

### 4. InheritanceEngine (`inheritance_engine.py`)
- BFS for hierarchy resolution
- Interface-to-interface tracking
- Caching for performance

### 5. FridaEngine (`frida_engine.py`)
- Generates Java hooks with overload support
- Argument inference via DFA
- Constructor detection ($init)

### 6. UIEngine (`ui_engine.py`)
- Resource ID mapping (public.xml / R.smali)
- Layout-to-code tracing
- Event handler discovery

### 7. BehaviorEngine (`behavior_engine.py`)
- Fingerprint-based detection
- Taint flow correlation
- High-confidence behavioral analysis

### 8. ReasoningEngine (`reasoning_engine.py`)
- Cross-engine correlation
- AI-ready summary generation

### 9. VariableFlowTracker (`variable_flow_tracker.py`)
- **Inter-procedural variable tracking**: Rastreia variável através de múltiplos métodos
- **Field tracking**: Suporte a leitura/escrita de campos (field)
- **Branch analysis**: Rastreamento em ramificações (if, switch)
- **Depth control**: Profundidade configurável (padrão: 10)
- **Usage points**: Registra cada operação com a variável

### 10. ObfuscationDetector (`obfuscation_engine.py`)
- **Reflection detection**: Class.forName, Method.invoke, Constructor.newInstance
- **String decryption**: Base64, XOR, custom crypto, byte arrays
- **Native code**: System.load, loadLibrary, Runtime.load, JNI
- **Risk assessment**: Avalia nível de obfuscação

### 11. AdvancedTrackingEngine (`advanced_tracking_engine.py`)
- **Sensitive sources**: Credentials, Device Info, Location, PII, Biometric, Camera, Mic
- **Exfiltration sinks**: Network, File, SharedPrefs, Database, Log, Clipboard, Intent, Bundle
- **Crypto detection**: Cipher, SecretKeySpec, MessageDigest
- **Data flow matching**: Associa sources a sinks
- **Risk assessment**: Gera recomendações de segurança
- **Cross-method flows**: Detecta fluxos entre métodos
- **Method chaining**: Detecta padrões builder (StringBuilder, OkHttp)
- **URL extraction**: Detecta URLs com parâmetros sensíveis

## Operational Capabilities

- **Atomic Bytecode Patching:** Safe modification of Smali files using transactional OS-level operations.
- **Forensic Indexing:** High-performance indexing of multi-dex environments with "First-Match" priority resolution (Android parity).
- **Interface-Aware Analysis:** Recursive tracking of class hierarchies and implemented interfaces for deep forensic markers.
- **UI-to-Code Tracing:** Dual-mode resource mapping via `public.xml` or `R.smali` fallback for production APKs.
- **Cross-Reference Analysis:** Recursive tracking of method invocation and field access chains.
- **Semantic Reconstruction:** Translation of flat bytecode into structured, taint-aware pseudocode.
- **Advanced Taint Tracking:** Support for string and integer constant propagation (`const`, `const/4`, etc.).
- **Manifest Forensics:** Automated identification of risky permissions and persistent malware triggers.
- **Frida Bridge:** Automated generation of Java-layer instrumentation scripts with constructor support ($init).

## Command Line Interface

| Option | Function |
| :--- | :--- |
| `--manifest` | Audit entry points, permissions, and security flags in AndroidManifest.xml. |
| `--scan all` | Execute static analysis rules (vulnerabilities, hardcoded secrets). |
| `--brain` | Generate a technical profile of a target class and its inheritance. |
| `--hook` | Inject instrumentation hooks into target methods. |
| `--frida` | Produce Frida instrumentation scripts with inferred argument naming. |
| `--xref` | Map method call chains and field usage. |
| `--cfg` | Export control-flow graphs in DOT format. |
| `--translate` | Translate Smali method to pseudocode. |
| `--ui-trace` | Trace UI elements to code handlers. |
| `--reason` | Generate AI reasoning summary. |
| `--resource-map` | Show resource ID mappings. |
| `--find-resource` | Find specific resource ID usage. |
| `--search` | Generic regex search. |
| `--patch-manifest` | Modify AndroidManifest flags. |
| `--generate-hook-class` | Generate ScoutHook.smali. |
| `--graph` | Export class dependency graph. |
| `--export` | Serialize analysis results to JSON format. |
| `--track-var` | Track variable flow through methods (inter-procedural). |
| `--track-var-name` | Variable name to track (default: p2). |
| `--track-depth` | Maximum depth for variable tracking (default: 10). |
| `--detect-obfuscation` | Detect obfuscation techniques (reflection, strings, native). |
| `--obf-types` | Obfuscation types: reflection, strings, native, all. |
| `--obf-depth` | Depth for dynamic tracking (default: 3). |
| `--analyze-data-flow` | Analyze sensitive data flows in a class. |
| `--data-flow-depth` | Depth for data flow analysis (default: 2). |

## Known Limitations

- **Regex-based analysis**: Not a full AST parser
- **No dynamic analysis**: Static-only
- **Multidex ambiguity**: First-match resolution may not always match runtime
- **16KB header assumption**: Class parsing assumes .class/.super in first 16KB

## Deployment & Verification

The toolkit is designed for integration into CI/CD pipelines and professional security workflows. Verification is conducted via the included comprehensive test suite:

```bash
python3 -m unittest discover tests/
```

Or with pytest:

```bash
pytest tests/ -v
```

## File Structure

```
scout/
├── smali_scout.py          # Main CLI (2730 lines)
├── tracking_engine.py     # XREF + Taint analysis
├── variable_flow_tracker.py # Inter-procedural variable tracking
├── obfuscation_engine.py  # Obfuscation detection (reflection, native)
├── advanced_tracking_engine.py # Sources/sinks, crypto, data flow
├── cfg_engine.py          # Control flow graphs
├── semantic_engine.py     # Pseudocode translation
├── inheritance_engine.py  # Hierarchy resolution
├── frida_engine.py        # Hook generation
├── ui_engine.py           # UI tracing
├── behavior_engine.py     # Behavioral fingerprints
├── reasoning_engine.py    # AI summaries
├── scout_knowledge.py    # SQLite knowledge base
├── tests/                 # Test suite (26+ files, 150+ tests)
├── README.md              # This file
└── HEURISTICS.md          # Analysis protocols
```

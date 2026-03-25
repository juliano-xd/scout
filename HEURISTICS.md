# Forensic Analysis Protocols

This document defines the technical workflows, operational constraints, and known issues for the Scout analysis engine.

## Standard Analysis Workflow

1. **Reconnaissance:** Execute `--manifest` to identify entry points (Activities, Services, Receivers).
2. **Static Scan:** Execute `--scan all` to identify common security misconfigurations (WebViews, debug flags).
3. **Component Profiling:** Use `--brain` for target classes. The engine performs automatic inheritance resolution to identify component archetypes.
4. **Data-Flow Mapping:** Use `--xref` with depth control to trace data propagation through call chains.
5. **Control Flow Analysis:** Use `--cfg` to export the logic graph for manual or automated auditing.
6. **Semantic Translation:** Use `--translate` to convert Smali to readable pseudocode.
7. **Instrumentation Pipeline:**
   - Generate Frida scripts with `--frida`.
   - Inject static logging hooks with `--hook`.
8. **Reporting:** Audit the generated `scout_report.json` for technical findings.

## Operational Rules

- **Signature Format:** Use full Smali FQDN: `Lpackage/Class;->Method(ParameterDescriptors)ReturnTypeDescriptor`.
- **Atomic Swap:** Every `--hook` operation uses atomic file replacement to ensure bytecode integrity.
- **Cache Management:** In-memory indices are invalidated upon patching to maintain consistency.
- **Multidex Priority:** In case of class collisions across DEX files, the first occurrence is used (matches Android runtime behavior).
- **Recursive Inheritance:** `is_instance_of` uses BFS to resolve hierarchies including interface-to-interface inheritance.
- **Backups:** Recovery files are preserved with a `.bak_timestamp` suffix.

## Advanced Forensic Triggers

- **Malware Persistence:** Automated flagging of receivers for `BOOT_COMPLETED`, `PACKAGE_ADDED`, and `QUICKBOOT_POWERON`.
- **Risky Permissions:** Prioritized scanning for `SYSTEM_ALERT_WINDOW`, `READ_SMS`, and `RECEIVE_SMS`.
- **Semantic Taints:** Identification of integer-based encryption modes and sensitive API flags via `const/4` tracking.
- **UI Hybrid Mapping:** Fallback to `R.smali` parsing when `public.xml` is obfuscated or missing.

## Known Issues & Limitations

### Indexing Engine
- **16KB Header Limit**: `_build_index` reads only first 16KB of each file. Classes with extremely large field declarations may fail to parse correctly.
- **Encoding Assumptions**: UTF-8 with `errors='ignore'` - may lose information with other encodings.

### Taint Tracking
- **Regex Limitations**: Constant string regex may fail with complex escape sequences.
- **Register Tracking**: `move-result` handling can miss connections in complex control flow.
- **Incomplete Type Inference**: Only basic type inference (URL, Base64) is implemented.

### CFG Generation
- **Switch Tables**: Sparse-switch handling is incomplete.
- **Exception Mapping**: Block indexing can be imprecise for complex exception handlers.

### Frida Generation
- **Static Method Detection**: Only checks first 20 lines of method body.
- **Type Parsing**: Some complex generic types may not parse correctly.

### Performance Considerations
- **XREF Depth**: Depth > 3 may cause high memory overhead in large DEX files.
- **Search Limits**: 1000 results max by default, 100 matches per file.

## Behavioral Fingerprints

The BehaviorEngine detects these patterns:

| Pattern | Components |
|---------|------------|
| DATA_EXFILTRATION | TelephonyManager.getDeviceId + HttpURLConnection |
| CRYPTO_SENSITIVE | Cipher.init/doFinal, SecretKeySpec |
| ANTI_ANALYSIS | isDebuggerConnected, System.exit |
| LOCATION_TRACKING | LocationManager, LocationListener |
| CONFIRMED_DATA_LEAK | Taint flow: IMEI → Network |

## Scanner Modules

| Module | Patterns |
|--------|----------|
| files | openFileOutput |
| webview | setJavaScriptEnabled |
| crypto | Cipher, MessageDigest, SecretKeySpec |
| strings | const-string |
| integers | 0x..., decimal |

## Error Codes

| Code | Meaning |
|------|---------|
| SUCCESS | Operation completed |
| INVALID_SIGNATURE | Malformed method/class signature |
| CLASS_NOT_FOUND | Target class not in index |
| FILE_NOT_FOUND | Smali file not found |
| INDEXING_FAILED | Could not build class index |
| SCAN_FAILED | Scanner encountered error |
| PATCH_FAILED | Hook injection failed |
| PERMISSION_DENIED | File access error |

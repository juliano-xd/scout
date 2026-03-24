# AI HEURISTICS & REASONING PROTOCOLS 🤖🧠

This document is a metadata layer designed for AI Agents (LLMs) interacting with the **SmaliScoutAI v19** framework.

## 🧠 Core Reasoning Loop (Suggested)
To analyze an APK effectively, an AI should follow this protocol:
1. **Reconnaissance:** Run `--manifest` to identify the Entry Points (Activities/Services).
2. **Vulnerability Scan:** Run `--scan all` to find low-hanging fruit (WebViews, World-Readable files).
3. **Deep Dive:** Choose a target class (e.g., from XREF or Scan results) and run `--brain "Lclass;"`.
4. **Instrumentation:**
    - Perform static patch via `--hook` if a permanent bypass is needed.
    - Generate Frida script via `--frida` for real-time traffic/logic observation.
5. **Verification:** Check `smaliscout_sys_v19.json` to confirm all findings were logged.

## 🛡️ Critical Operational Rules
- **Signature Format:** ALWAYS use the full Smali FQDN signature: `Lpackage/Class;->Method(ParameterDescriptors)ReturnTypeDescriptor`.
- **Dex Priority:** The indexer automatically handles multi-dex. Trust the `resolve_class` logic; it prioritizes the highest `smali_classesN` folder.
- **Atomic Safeguard:** You cannot "break" a file. Every `--hook` triggers an OS-level atomic swap. If the tool reports `SUCCESS`, the file is valid Smali.
- **Cache Invalidation:** The memory cache is invalidated after every patch. You can run incremental analysis without restarting the tool.

## 🚨 Universal Smali Patterns to Lookout for
- **Entry Point Identification:** Check classes that extend `Landroid/app/Activity;`, `Landroid/app/Service;`, or `Landroid/content/BroadcastReceiver;`.
- **API Fingerprinting:** Look for calls to `Landroid/net/Uri;->parse` (Net calls), `Landroid/content/SharedPreferences;` (Data storage), or `Landroid/util/Log;` (Debugging).
- **Control Flow:** Focus on `invoke-virtual` calls to sensitive system APIs compared to `invoke-direct` for internal logic.
- **Data Persistence:** Monitor `const-string` signatures followed by `openFileOutput` or `SQLiteDatabase` operations.
- **Network Recon:** Identify URLs and IP addresses by scanning for `const-string` inputs to `Ljava/net/URL;` or `Lokhttp3/Request$Builder;`.

## 📎 AI-Parser Hints
- **JSON Structure:** Root field `findings` is the main data hub.
- **Status Tags:** Look for `[INFO]`, `[ERROR]`, and `[!] VULN` in console output for quick parsing.
- **Backups:** If recovery is needed, look for Files ending in `.bak_timestamp`.
- **Atomic Swap:** Every patch is transactional. A `SUCCESS` status in the report guarantees a syntactically valid Smali file.

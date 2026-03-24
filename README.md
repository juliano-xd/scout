# SmaliScoutAI v19 - Systemic Edition 🕵️‍♂️⚙️💎

**Universal Smali Intelligence & Bytecode Engineering Framework.**

SmaliScoutAI is a professional-grade Android reverse engineering toolkit designed for automated forensic analysis, security auditing, and safe bytecode injection. It is structurally optimized for **AI Agent Interoperability**.

## 🚀 Key AI-Native Features
- **Atomic Transactional Patching:** Uses `os.replace` for OS-level atomic file swaps. 0% risk of file corruption.
- **Global Class Indexer:** Instant FQDN resolution (`Lclass;`) across all dex folders (`smali_classes1..N`) with numeric-aware sorting.
- **Memory-Safe LRU Cache:** Capable of scanning 100k+ classes without OOM (Out of Memory) errors.
- **Deep Manifest Recon:** Unified reconnaissance of Android surfaces, capturing both explicit and implicit (Intent-Filter) entry points.
- **Parametric Frida Generator:** Automatic generation of overloaded Frida hooks for complex JVM signatures.

## 🛠️ CLI Usage (AI Master Protocol)
| Flag | Target | AI Purpose |
| :--- | :--- | :--- |
| `--manifest` | None | Map the application attack surface (Activities, Services, Providers). |
| `--scan all` | {vuln, crypto} | Bulk audit for security flaws and cryptographic algorithms. |
| `--brain` | `Lclass;` | Deep I/O flow analysis and API fingerprinting of a specific class. |
| `--hook` | `Lclass;->method()` | Transactional bytecode injection using established templates. |
| `--frida` | `Lclass;->method()` | Generate a ready-to-use `.js` hook script for dynamic analysis. |
| `--export` | None | Output the full audit trail into `smaliscout_sys_v19.json`. |

## 🏗️ System Architecture
1. **Core:** Python 3.x using `pathlib` and `ET` (XML).
2. **Persistence:** Centralized `report_data` dictionary exported as JSON.
3. **Safety:** Automatic timestamped backups (`.bak_YYYYMMDD_HHMMSS`) before any modification.
4. **Performance:** Multi-threaded indexing (`ThreadPoolExecutor`) + LRU Cache Strategy.

---
*Created by Antigravity v19 - Engineered for the next generation of Reverse Engineering Agents.*

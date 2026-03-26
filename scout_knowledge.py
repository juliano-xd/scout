#!/usr/bin/env python3

import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ScoutKnowledge")

class ScoutKnowledge:
    """
    Manages the 'Universal Understandings' database for Scout. 
    Stores framework signatures, DFA hints, and common API patterns.
    """

    def __init__(self, db_path: str = "scout_knowledge.db"):
        self.db_path = db_path
        self._framework_cache: Dict[str, str] = {}
        self._dfa_cache: List[Tuple[str, str]] = []
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and pre-populates it with universal truths."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Table for known framework classes (Inheritance)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS framework_classes (
                signature TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                category TEXT
            )
        """)

        # Table for DFA Hints (Parameter Usage)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dfa_hints (
                api_signature TEXT PRIMARY KEY,
                param_label TEXT NOT NULL
            )
        """)

        # Pre-populate if empty
        cursor.execute("SELECT COUNT(*) FROM framework_classes")
        if cursor.fetchone()[0] == 0:
            self._prefill_framework(cursor)
            self._prefill_dfa_hints(cursor)

        conn.commit()
        
        # Load Cache
        cursor.execute("SELECT signature, label FROM framework_classes")
        self._framework_cache = dict(cursor.fetchall())
        
        cursor.execute("SELECT api_signature, param_label FROM dfa_hints")
        self._dfa_cache = cursor.fetchall()
        
        conn.close()

    def _prefill_framework(self, cursor):
        """Pre-populates the database with well-known Android/Java framework classes."""
        known_bases = [
            # Android Core
            ("Landroid/app/Activity;", "activity", "Android_Core"),
            ("Landroid/app/Application;", "application", "Android_Core"),
            ("Landroid/app/Service;", "service", "Android_Core"),
            ("Landroid/content/BroadcastReceiver;", "receiver", "Android_Core"),
            ("Landroid/content/ContentProvider;", "provider", "Android_Core"),
            ("Landroid/app/Fragment;", "fragment", "Android_Core"),
            ("Landroidx/fragment/app/Fragment;", "fragment", "Android_Core"),
            ("Landroid/view/View;", "view", "Android_UI"),
            ("Landroid/view/ViewGroup;", "viewgroup", "Android_UI"),
            ("Landroid/app/Dialog;", "dialog", "Android_UI"),
            # Context & Comm
            ("Landroid/content/Context;", "context", "Android_Core"),
            ("Landroid/content/Intent;", "intent", "Android_Core"),
            ("Landroid/os/Bundle;", "bundle", "Android_OS"),
            ("Landroid/os/Handler;", "handler", "Android_OS"),
            ("Landroid/os/IBinder;", "binder", "Android_OS"),
            ("Landroid/os/IInterface;", "interface", "Android_OS"),
            ("Landroid/os/Message;", "message", "Android_OS"),
            # Networking
            ("Ljava/net/URL;", "url", "Network"),
            ("Ljava/net/HttpURLConnection;", "http_conn", "Network"),
            ("Lokhttp3/OkHttpClient;", "okhttp", "Network"),
            ("Lokhttp3/Request;", "request", "Network"),
            ("Lokhttp3/Response;", "response", "Network"),
            ("Lokhttp3/Call;", "call", "Network"),
            ("Lokhttp3/WebSocket;", "websocket", "Network"),
            ("Lretrofit2/Retrofit;", "retrofit", "Network"),
            # Persistence
            ("Landroid/content/SharedPreferences;", "prefs", "Storage"),
            ("Landroid/database/sqlite/SQLiteOpenHelper;", "db_helper", "Storage"),
            ("Landroid/database/sqlite/SQLiteDatabase;", "db", "Storage"),
            ("Landroid/database/Cursor;", "cursor", "Storage"),
            ("Lorg/json/JSONObject;", "json_obj", "Data"),
            ("Lorg/json/JSONArray;", "json_arr", "Data"),
            ("Lcom/google/gson/Gson;", "gson", "Data"),
            # Java Core
            ("Ljava/lang/String;", "str", "Java_Core"),
            ("Ljava/lang/StringBuilder;", "sb", "Java_Core"),
            ("Ljava/util/List;", "list", "Java_Core"),
            ("Ljava/util/ArrayList;", "list", "Java_Core"),
            ("Ljava/util/Map;", "map", "Java_Core"),
            ("Ljava/util/HashMap;", "map", "Java_Core"),
            ("Ljava/io/File;", "file", "IO"),
            ("Ljava/io/InputStream;", "istr", "IO"),
            ("Ljava/io/OutputStream;", "ostr", "IO"),
            # Arch & Concurrency
            ("Landroidx/lifecycle/ViewModel;", "viewmodel", "Architecture"),
            ("Landroidx/lifecycle/LiveData;", "livedata", "Architecture"),
            ("Ljava/lang/Thread;", "thread", "OS"),
            ("Ljava/lang/Runnable;", "runnable", "OS"),
            ("Ljava/lang/Exception;", "error", "Java_Core"),
            ("Ljava/lang/Throwable;", "error", "Java_Core"),
        ]
        cursor.executemany("INSERT INTO framework_classes VALUES (?, ?, ?)", known_bases)

    def _prefill_dfa_hints(self, cursor):
        """Pre-populates the database with universal DFA parameter hints."""
        hints = [
            ("Ljava/net/URL;", "url"),
            ("Ljava/lang/String;->indexOf", "search_str"),
            ("Ljava/io/File;", "file"),
            ("Landroid/content/Context;", "context"),
            ("Landroid/content/Intent;", "intent"),
            ("Lorg/json/", "json_data"),
            ("Ljava/lang/StringBuilder;->append", "text_part"),
            ("Ljavax/crypto/Cipher;->init", "crypto_mode"),
            ("Landroid/database/sqlite/SQLiteDatabase;->execSQL", "sql_query"),
            ("Landroid/util/Log;", "log_msg")
        ]
        cursor.executemany("INSERT INTO dfa_hints VALUES (?, ?)", hints)

    def get_framework_label(self, signature: str) -> Optional[str]:
        """Looks up a framework class label (using Memory Cache)."""
        return self._framework_cache.get(signature)

    def get_dfa_hint(self, api_signature: str) -> Optional[str]:
        """Looks up a DFA parameter hint (using Memory Cache)."""
        for pattern, label in self._dfa_cache:
            if pattern in api_signature:
                return label
        return None

    def add_understanding(self, sig: str, label: str, category: str = "Learned"):
        """Adds a new universal understanding to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO framework_classes VALUES (?, ?, ?)", (sig, label, category))
        conn.commit()
        conn.close()
        
        # Sync Cache
        self._framework_cache[sig] = label
        logger.info(f"[DB] Learned new understanding: {sig} -> {label}")

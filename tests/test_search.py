import unittest
import re
from pathlib import Path
from smali_scout import SearchEngine, LRUCache

class TestSearchEngine(unittest.TestCase):
    def setUp(self):
        self.cache = LRUCache(10)
        self.index = {
            "Ltest/A;": [Path("smali/A.smali")],
            "Ltest/B;": [Path("smali/B.smali")]
        }
        # Inject mock content into cache
        self.cache.put(Path("smali/A.smali"), ".class Ltest/A;\nconst-string v0, \"API_KEY_123\"\ninvoke-static {v0}, Lokhttp3/OkHttpClient;-><init>()V")
        self.cache.put(Path("smali/B.smali"), ".class Ltest/B;\nconst-string v1, \"http://example.com\"")
        
        self.engine = SearchEngine(self.index, self.cache)

    def test_regex_search(self):
        """Verify regex-based string literal search."""
        results = self.engine.search(r"API_KEY_\d+", search_type="regex")
        self.assertEqual(results["total_matches"], 1)
        self.assertEqual(results["results"][0]["class"], "Ltest/A;")

    def test_pattern_search_invoke(self):
        """Verify optimized pattern search for opcodes."""
        results = self.engine.search("OkHttpClient", search_type="invoke")
        self.assertEqual(results["total_matches"], 1)
        self.assertIn("OkHttpClient", results["results"][0]["match"])

    def test_exclude_dirs(self):
        """Verify directory exclusion logic."""
        results = self.engine.search("const-string", exclude_dirs=["smali/A.smali"])
        # Should only find results in B
        classes = {r["class"] for r in results["results"]}
        self.assertIn("Ltest/B;", classes)
        self.assertNotIn("Ltest/A;", classes)

if __name__ == "__main__":
    unittest.main()


class TestSearchEngineAdvanced(unittest.TestCase):
    """Advanced search engine tests."""

    def setUp(self):
        self.cache = LRUCache(10)
        self.index = {
            "Ltest/A;": [Path("smali/A.smali")],
            "Ltest/B;": [Path("smali/B.smali")],
        }
        self.cache.put(Path("smali/A.smali"), ".class Ltest/A;\nconst-string v0, \"password\"\ninvoke-static {v0}, Lcom/test/Auth;->login()V")
        self.cache.put(Path("smali/B.smali"), ".class Ltest/B;\nconst-string v1, \"https://api.com\"")
        
        self.engine = SearchEngine(self.index, self.cache)

    def test_basic_search(self):
        """Test basic search returns results."""
        results = self.engine.search("const-string", search_type="regex")
        self.assertIsInstance(results, dict)
        self.assertIn("total_matches", results)

    def test_url_detection(self):
        """Test URL pattern detection."""
        results = self.engine.search(r"https?://", search_type="regex")
        self.assertGreaterEqual(results["total_matches"], 1)

    def test_credentials_detection(self):
        """Test credentials pattern detection."""
        results = self.engine.search(r"password", search_type="regex")
        self.assertGreaterEqual(results["total_matches"], 1)

    def test_method_search(self):
        """Test method search."""
        results = self.engine.search("Auth", search_type="invoke")
        self.assertIsInstance(results, dict)


class TestLRUCache(unittest.TestCase):
    """Test LRU Cache implementation."""

    def test_cache_basic(self):
        """Test basic cache put/get."""
        cache = LRUCache(10)
        cache.put("key", "value")
        self.assertEqual(cache.get("key"), "value")

    def test_cache_miss(self):
        """Test cache miss returns None."""
        cache = LRUCache(10)
        self.assertIsNone(cache.get("nonexistent"))


if __name__ == "__main__":
    unittest.main()

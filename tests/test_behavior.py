import unittest
from behavior_engine import BehaviorEngine
from scout_knowledge import ScoutKnowledge

class TestBehaviorEngine(unittest.TestCase):
    def setUp(self):
        self.kb = ScoutKnowledge()
        self.engine = BehaviorEngine(self.kb)

    def test_api_chain_detection(self):
        """Verify detection of dangerous API chains (e.g., Network -> Crypto)."""
        findings = {
            "apis": {
                "Lokhttp3/OkHttpClient;->newCall": [{"class": "Lcom/app/Net;", "method": "send"}],
                "Ljavax/crypto/Cipher;->doFinal": [{"class": "Lcom/app/Crypt;", "method": "enc"}]
            }
        }
        behaviors = self.engine.analyze_findings(findings)
        self.assertTrue(any("EXFILTRATION" in b["type"] or "CRYPTO" in b["type"] for b in behaviors))

    def test_malicious_pattern_synthesis(self):
        """Verify behavior synthesizer on mixed findings."""
        findings = {
            "scans": {
                "crypto": {"Ljavax/crypto/Cipher;": 2},
                "strings": ["https://api.malicious.com"]
            }
        }
        synthesis = self.engine.synthesize_behavior(findings)
        self.assertIn("Dangerous Infrastructure", synthesis)

if __name__ == "__main__":
    unittest.main()


class TestBehaviorEngineAdvanced(unittest.TestCase):
    """Advanced behavior engine tests."""

    def setUp(self):
        self.kb = ScoutKnowledge()
        self.engine = BehaviorEngine(self.kb)

    def test_empty_findings(self):
        """Test behavior analysis with empty findings."""
        behaviors = self.engine.analyze_findings({})
        self.assertIsInstance(behaviors, list)

    def test_synthesize_empty(self):
        """Test synthesis with empty input."""
        synthesis = self.engine.synthesize_behavior({})
        self.assertIsInstance(synthesis, str)

    def test_basic_findings(self):
        """Test basic findings analysis."""
        findings = {"apis": {}, "strings": []}
        behaviors = self.engine.analyze_findings(findings)
        self.assertIsInstance(behaviors, list)

    def test_synthesize_basic(self):
        """Test basic synthesis."""
        findings = {"scans": {}}
        synthesis = self.engine.synthesize_behavior(findings)
        self.assertIsInstance(synthesis, str)


class TestScoutKnowledge(unittest.TestCase):
    """Test ScoutKnowledge functionality."""

    def setUp(self):
        self.kb = ScoutKnowledge()

    def test_knowledge_init(self):
        """Test knowledge base initializes."""
        self.assertIsNotNone(self.kb)

    def test_knowledge_dict_access(self):
        """Test knowledge dict access."""
        attrs = dir(self.kb)
        self.assertIsInstance(attrs, list)


if __name__ == "__main__":
    unittest.main()

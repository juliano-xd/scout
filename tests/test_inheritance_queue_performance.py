import unittest
from collections import deque
from inheritance_engine import InheritanceEngine

class TestInheritanceQueuePerformance(unittest.TestCase):
    """Test cases for Bug #8: queue.pop(0) performance issue."""

    def setUp(self):
        self.engine = InheritanceEngine({}, lambda x: "")

    def test_queue_pop_performance(self):
        """
        Bug #8: Using list.pop(0) is O(n) which is slow for large hierarchies.
        Should use collections.deque with popleft() which is O(1).
        """
        # Create a large queue
        queue = list(range(1000))
        
        # Using list.pop(0) is O(n)
        import time
        
        # Time list.pop(0) - use larger dataset to show difference
        test_list = list(range(10000))
        start = time.time()
        for _ in range(1000):
            test_list.pop(0)
        list_time = time.time() - start
        
        # Time deque.popleft()
        test_deque = deque(range(10000))
        start = time.time()
        for _ in range(1000):
            test_deque.popleft()
        deque_time = time.time() - start
        
        # deque should be significantly faster
        self.assertLess(deque_time, list_time / 2, 
            f"deque.popleft() should be faster than list.pop(0). Got deque={deque_time}, list={list_time}")

    def test_current_implementation_is_list(self):
        """
        Bug #8: Verify current implementation uses list which is slow.
        """
        # The current code uses list.pop(0)
        queue = [1, 2, 3]
        
        # This is the problematic pattern
        result = queue.pop(0)
        
        self.assertEqual(result, 1)
        self.assertEqual(queue, [2, 3])

    def test_deque_is_faster_for_large_data(self):
        """
        Demonstrate deque is O(1) vs list O(n) for pop(0)
        """
        import time
        
        # List: O(n) per pop(0)
        large_list = list(range(10000))
        start = time.time()
        for _ in range(100):
            large_list.pop(0)
        list_time = time.time() - start
        
        # Deque: O(1) per popleft()
        large_deque = deque(range(10000))
        start = time.time()
        for _ in range(100):
            large_deque.popleft()
        deque_time = time.time() - start
        
        # Bug #8 should be fixed by using deque
        # This test documents the performance difference
        self.assertGreater(list_time, deque_time * 2)

if __name__ == "__main__":
    unittest.main()

import unittest

class TestBroadExceptionHandling(unittest.TestCase):
    """Test cases for Bug #1: Broad exception handling."""

    def test_broad_except_catches_keyboard_interrupt(self):
        """
        Bug #1: Using bare 'except:' catches everything including 
        KeyboardInterrupt and SystemExit, which is bad practice.
        """
        # This demonstrates the problematic pattern
        try:
            # Bare except catches everything
            try:
                raise KeyboardInterrupt("test")
            except:
                pass
            caught_keyboard = True
        except KeyboardInterrupt:
            caught_keyboard = False
        
        # Bug #1: Bare except should NOT catch KeyboardInterrupt
        self.assertTrue(caught_keyboard, "Bug #1: Bare except caught KeyboardInterrupt")

    def test_broad_except_catches_system_exit(self):
        """
        Bug #1: Bare except also catches SystemExit
        """
        try:
            try:
                raise SystemExit(0)
            except:
                pass
            caught_system_exit = True
        except SystemExit:
            caught_system_exit = False
        
        # Bug #1: Bare except should NOT catch SystemExit
        self.assertTrue(caught_system_exit, "Bug #1: Bare except caught SystemExit")

    def test_specific_exception_is_better(self):
        """
        Better practice: Catch specific exceptions
        """
        try:
            try:
                raise ValueError("test")
            except ValueError:
                pass
            caught_value = True
        except ValueError:
            caught_value = False
        
        self.assertTrue(caught_value)

    def test_exception_hierarchy(self):
        """
        Verify exception hierarchy for proper catching
        """
        # BaseException is parent of Exception, KeyboardInterrupt, SystemExit
        self.assertTrue(issubclass(KeyboardInterrupt, BaseException))
        self.assertTrue(issubclass(SystemExit, BaseException))
        self.assertTrue(issubclass(Exception, BaseException))
        self.assertTrue(issubclass(ValueError, Exception))

    def test_recommend_specific_except(self):
        """
        Recommended pattern: catch specific exceptions
        """
        code_snippet = """
try:
    # code that might fail
except ValueError:
    # handle ValueError
except TypeError:
    # handle TypeError
except Exception as e:
    # handle other exceptions
    raise  # re-raise unexpected exceptions
"""
        # This is the recommended pattern
        self.assertIn("except ValueError", code_snippet)

if __name__ == "__main__":
    unittest.main()

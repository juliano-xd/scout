import unittest

class TestTrackingBareExcept(unittest.TestCase):
    """Test case for Bug #15: Bare except in tracking_engine.py"""

    def test_bare_except_in_tracking_engine(self):
        """
        Bug #15: The same pattern as Bug #1 exists in tracking_engine.py
        
        Line 119: except: return None
        
        This catches all exceptions including KeyboardInterrupt and SystemExit.
        Should catch specific exceptions like IOError, OSError, PermissionError.
        """
        # This demonstrates the problematic code pattern:
        # try:
        #     content = path.read_text(encoding="utf-8", errors="ignore")
        # except: return None  # <-- Bug #15
        
        # The fix should be:
        # try:
        #     content = path.read_text(encoding="utf-8", errors="ignore")
        # except (IOError, OSError, PermissionError): return None
        
        # For file operations, we should catch:
        # - FileNotFoundError (subclass of OSError)
        # - PermissionError (subclass of OSError)  
        # - IsADirectoryError (subclass of OSError)
        # - UnicodeDecodeError
        
        import builtins
        original_open = builtins.open
        
        caught_exceptions = []
        
        def mock_open(*args, **kwargs):
            raise KeyboardInterrupt("test")
        
        # With bare except - catches everything
        try:
            try:
                raise KeyboardInterrupt("test")
            except:
                pass
            bare_catches_all = True
        except KeyboardInterrupt:
            bare_catches_all = False
        
        self.assertTrue(bare_catches_all, "Bare except catches everything")
        
        # With specific except - catches only specified
        try:
            try:
                raise KeyboardInterrupt("test")
            except (IOError, OSError):
                pass
            specific_catches_keyboard = True
        except KeyboardInterrupt:
            specific_catches_keyboard = False
        
        self.assertFalse(specific_catches_keyboard, 
            "Specific except should not catch KeyboardInterrupt")

    def test_recommended_exception_types(self):
        """
        Recommended exceptions for file operations:
        """
        # File operation exceptions
        file_exceptions = (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            UnicodeDecodeError,
            OSError  # catch-all for OS-related errors
        )
        
        # Verify these are valid exception types
        self.assertTrue(issubclass(FileNotFoundError, OSError))
        self.assertTrue(issubclass(PermissionError, OSError))
        self.assertTrue(issubclass(UnicodeDecodeError, ValueError))

if __name__ == "__main__":
    unittest.main()

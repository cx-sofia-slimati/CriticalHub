"""
Basic tests for utility functions
"""
import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessPickleFile(unittest.TestCase):
    """process_pickle_file must never unpickle uploaded data"""

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _write(self, name, data):
        path = os.path.join(self.tmpdir.name, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def test_json_content_is_parsed(self):
        from utils.file_handler import process_pickle_file
        path = self._write('ok.pkl', b'{"a": 1, "b": [1, 2]}')
        self.assertEqual(process_pickle_file(path), {'a': 1, 'b': [1, 2]})

    def test_malicious_pickle_is_not_executed(self):
        import pickle
        from utils.file_handler import process_pickle_file

        marker = os.path.join(self.tmpdir.name, 'pwned')

        class Evil:
            def __reduce__(self):
                return (open, (marker, 'w'))

        path = self._write('evil.pkl', pickle.dumps(Evil()))
        result = process_pickle_file(path)

        self.assertIn('error', result)
        self.assertFalse(os.path.exists(marker))

    def test_missing_file_returns_error(self):
        from utils.file_handler import process_pickle_file
        result = process_pickle_file(os.path.join(self.tmpdir.name, 'nope.pkl'))
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()


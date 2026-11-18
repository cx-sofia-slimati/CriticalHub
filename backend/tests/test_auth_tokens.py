"""
Tests for JWT token expiration enforcement in auth.py
"""
import unittest
import sys
import os
from datetime import datetime, timedelta

import jwt

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth import generate_token, verify_token, JWT_SECRET
from config import Config


class TestJwtExpiration(unittest.TestCase):
    """Tokens must carry and enforce an expiration claim"""

    def test_generated_token_has_exp_claim(self):
        token = generate_token(1, 'alice')
        payload = jwt.decode(token, JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
        self.assertIn('exp', payload)
        self.assertGreater(payload['exp'], payload['iat'])

    def test_generated_token_verifies(self):
        token = generate_token(1, 'alice')
        payload = verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['user_id'], 1)
        self.assertEqual(payload['username'], 'alice')

    def test_token_without_exp_is_rejected(self):
        """A legacy / forged non-expiring token must not be accepted"""
        token = jwt.encode(
            {'user_id': 1, 'username': 'alice', 'iat': datetime.utcnow()},
            JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM,
        )
        self.assertIsNone(verify_token(token))

    def test_expired_token_is_rejected(self):
        now = datetime.utcnow()
        token = jwt.encode(
            {
                'user_id': 1,
                'username': 'alice',
                'iat': now - timedelta(hours=2),
                'exp': now - timedelta(hours=1),
            },
            JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM,
        )
        self.assertIsNone(verify_token(token))


if __name__ == '__main__':
    unittest.main()

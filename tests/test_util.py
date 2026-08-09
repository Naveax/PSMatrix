import tempfile
import unittest
from pathlib import Path

from psmatrix.util import exclusive_lock


class UtilTests(unittest.TestCase):
    def test_exclusive_lock_can_be_acquired_released_and_reacquired(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / "locks" / "operation.lock"
            with exclusive_lock(lock):
                self.assertTrue(lock.is_file())
            with exclusive_lock(lock):
                self.assertTrue(lock.is_file())


if __name__ == "__main__":
    unittest.main()

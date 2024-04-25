import os
import shutil
import tempfile
import unittest

from shadycompass import FileMetadataCache


class FileMetadataCacheTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.tempdir = tempfile.mkdtemp()
        shutil.copytree('tests/fixtures/nmap', self.tempdir, dirs_exist_ok=True)
        shutil.copytree('tests/fixtures/etchosts', self.tempdir, dirs_exist_ok=True)
        file_path = os.path.join(self.tempdir, 'hosts2')
        with open(file_path, 'wt') as fd:
            fd.write('127.0.0.3 localhost3')
        self.cache = FileMetadataCache([self.tempdir, file_path])

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super().tearDown()

    def test_initial_find_changes(self):
        changes = self.cache.find_changes()
        self.assertEqual(4, len(changes))

    def test_no_changes(self):
        self.cache.find_changes()
        changes = self.cache.find_changes()
        self.assertEqual(0, len(changes))

    def test_one_change(self):
        self.cache.find_changes()
        file_path = os.path.join(self.tempdir, 'open-ports.txt')
        with open(file_path, 'a') as fd:
            fd.write('touch')
        changes = self.cache.find_changes()
        self.assertEqual(1, len(changes))
        self.assertTrue(changes[0].endswith('/open-ports.txt'))
        changes = self.cache.find_changes()
        self.assertEqual(0, len(changes))

    def test_file_removed(self):
        self.cache.find_changes()
        os.remove(os.path.join(self.tempdir, 'open-ports.txt'))
        changes = self.cache.find_changes()
        self.assertEqual(1, len(changes))
        self.assertTrue(changes[0].endswith('/open-ports.txt'))
        changes = self.cache.find_changes()
        self.assertEqual(0, len(changes))

import os
import sys

FILE_SIZE_LIMIT = 10 * 1024 * 1024


class FileMetaData:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.stat = None
        self.update()

    def has_changed(self) -> bool:
        new_stat = os.stat(self.file_path, follow_symlinks=True)
        return new_stat.st_size != self.stat.st_size or new_stat.st_mtime != self.stat.st_mtime

    def update(self):
        self.stat = os.stat(self.file_path, follow_symlinks=True)


class FileMetadataCache:
    """
    Maintains a list of files in the directories we are watching. Checks for updates via file stats so that
    the facts can be updates.
    """

    def __init__(self, paths: list[str] = None):
        if not paths:
            self.paths = [os.getcwd()]
        else:
            self.paths = paths.copy()
        self.files: dict[str, FileMetaData] = dict()

    def find_changes(self) -> list[str]:
        changes: list[str] = list()
        removed = set(self.files.keys())
        for path in self.paths:
            if os.path.isfile(path):
                removed.discard(path)
                changes.extend(self._check_file_change(path))
            for root, _, files in os.walk(path, topdown=True):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path) and os.stat(file_path).st_size > FILE_SIZE_LIMIT:
                        # we'll fill up memory with very large files
                        print(f"[!] skipping {file_path} because file is larger than {FILE_SIZE_LIMIT} bytes", file=sys.stderr)
                        continue
                    removed.discard(file_path)
                    changes.extend(self._check_file_change(file_path))
        changes.extend(removed)
        for path in removed:
            self.files.pop(path)
        return changes

    def reset(self):
        self.files.clear()

    def _check_file_change(self, file_path: str) -> list[str]:
        if file_path in self.files:
            file_meta_data = self.files[file_path]
            if file_meta_data.has_changed():
                file_meta_data.update()
                return [file_path]
        elif os.path.isfile(file_path):
            self.files[file_path] = FileMetaData(file_path)
            return [file_path]
        return []

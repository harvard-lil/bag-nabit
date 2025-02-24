import os
import shutil
from pathlib import Path
from dataclasses import dataclass
from ..utils import get_unique_path
from .base import CollectionTask

@dataclass
class PathCollectionTask(CollectionTask):
    """Collect files or directories from the local filesystem."""
    backend = 'path'

    path: Path
    output: Path | None = None
    hard_links: bool = False

    ignore_patterns = ['.*']

    def __post_init__(self):
        """Validate the path and ensure it's a Path object."""
        self.path = Path(self.path)  # Coerce to Path if it's a string
        if not self.path.exists():
            raise ValueError(f'Path "{self.path}" does not exist')
        if self.output is not None:
            self.output = Path(self.output)  # Also coerce output if provided

    def _collect(self, files_dir: Path) -> Path:
        """Copy paths to a destination directory, optionally using hard links."""
        path = self.path
        dest_name = self.output or path.name
        dest_path = get_unique_path(files_dir / dest_name)
        # can only use hard links if source and destination are on the same device
        use_hard_links = self.hard_links and os.stat(path).st_dev == os.stat(files_dir).st_dev
        if path.is_file():
            if use_hard_links:
                os.link(path, dest_path)
            else:
                shutil.copy2(path, dest_path)
        else:
            copy_function = os.link if use_hard_links else shutil.copy2
            # link directory contents recursively
            shutil.copytree(
                path,
                dest_path,
                dirs_exist_ok=True,
                copy_function=copy_function,
                ignore=shutil.ignore_patterns(*self.ignore_patterns)
            )
        return {'path': str(dest_path.relative_to(files_dir))}

    def request_dict(self) -> dict:
        """Return a dictionary representation of the request."""
        return {
            'ignore_patterns': self.ignore_patterns,
        }

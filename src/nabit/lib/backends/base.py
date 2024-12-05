from dataclasses import dataclass, asdict
from functools import lru_cache
from pathlib import Path

@lru_cache
def get_backends() -> dict[str, type['CollectionTask']]:
    # do this in a cached function to avoid circular import
    from .url import UrlCollectionTask
    from .path import PathCollectionTask

    return {
        UrlCollectionTask.backend: UrlCollectionTask,
        PathCollectionTask.backend: PathCollectionTask,
    }

class CollectionError(Exception):
    """Base class for collection errors"""

@dataclass
class CollectionTask:
    @classmethod
    def from_dict(cls, data: dict) -> 'CollectionTask':
        backend = data.pop('backend')
        return get_backends()[backend](**data)

    def collect(self, files_dir: Path) -> dict:
        """Call the backend-specific _collect method and return the result, handling any errors."""
        try:
            result = self._collect(files_dir)
            result['success'] = True
        except Exception as e:
            result = {'success': False, 'error': str(e)}
        return {
            'request': self.request_dict(),
            'response': result,
        }
    
    def _collect(self, files_dir: Path) -> dict:
        """Collect the data to the given directory."""
        raise NotImplementedError

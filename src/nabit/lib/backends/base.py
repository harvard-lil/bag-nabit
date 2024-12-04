from dataclasses import dataclass
from functools import lru_cache

@lru_cache
def get_backends() -> dict[str, type['CollectionTask']]:
    # do this in a cached function to avoid circular import
    from .url import UrlCollectionTask
    from .path import PathCollectionTask

    return {
        'url': UrlCollectionTask,
        'path': PathCollectionTask,
    }

@dataclass
class CollectionTask:
    @classmethod
    def from_dict(cls, data: dict) -> 'CollectionTask':
        backend = data.pop('backend')
        return get_backends()[backend](**data)

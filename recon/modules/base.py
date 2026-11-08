'''
Base class shared by every collection module.
'''

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Generic, TypeVar

from recon.models import CollectionError

T = TypeVar("T")


class Collector(ABC, Generic[T]):
    '''
    A collection step: gathers evidence and returns structured observations, never findings.
    Subclasses set ``name`` and implement ``collect``.
    '''

    name: ClassVar[str]

    @abstractmethod
    async def collect(self) -> tuple[T | None, list[CollectionError]]:
        '''
        Run the collection step.
        Returns:
            tuple[T | None, list[CollectionError]]: Collected data (None if nothing usable) and recorded errors.
        Raises:
            Exception: Any unexpected failure; the orchestrator converts it into a FAILED result.
        '''

    def error(self, target: str | None, error_type: str, message: str) -> CollectionError:
        '''
        Build a CollectionError attributed to this module.
        Parameters:
            target (str | None): What the failed check was about.
            error_type (str): Machine-readable error type.
            message (str): Human-readable detail.
        Returns:
            CollectionError: The error record.
        '''
        return CollectionError(module=self.name, target=target, error_type=error_type, message=message)

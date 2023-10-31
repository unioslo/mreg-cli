from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Protocol

    class ResponseLike(Protocol):
        """Interface for objects that resemble a requests.Response object."""

        @property
        def ok(self) -> bool:
            ...

        @property
        def status_code(self) -> int:
            ...

        @property
        def reason(self) -> str:
            ...

        def json(self, **kwargs: Any) -> Any:
            ...

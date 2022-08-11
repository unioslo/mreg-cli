from typing import Literal, NoReturn, Optional, Type, overload


@overload
def cli_error(msg: str) -> NoReturn:
    ...


@overload
def cli_error(
    msg: str, raise_exception: Literal[True] = True, exception: Type[Exception] = ...
) -> NoReturn:
    ...


@overload
def cli_error(
    msg: str, raise_exception: Literal[False] = False, exception: Type[Exception] = ...
) -> None:
    ...


@overload
def cli_error(
    msg: str, raise_exception: bool = ..., exception: Type[Exception] = ...
) -> Optional[NoReturn]:
    ...

@overload
def cli_warning(msg: str) -> NoReturn:
    ...


@overload
def cli_warning(
    msg: str, raise_exception: Literal[True] = True, exception: Type[Exception] = ...
) -> NoReturn:
    ...


@overload
def cli_warning(
    msg: str, raise_exception: Literal[False] = False, exception: Type[Exception] = ...
) -> None:
    ...


@overload
def cli_warning(
    msg: str, raise_exception: bool = ..., exception: Type[Exception] = ...
) -> Optional[NoReturn]:
    ...



def cli_info(msg: str, print_msg: bool = ...) -> None:
    ...
"""Tiny PyQt5 stand-in so the non-GUI logic (crypto, saves, rotation, integrity) and the GUI *code paths* can be exercised without a display.
It is only used when PyQt5 is not installed. It cannot show real windows."""
import sys
import types
from collections.abc import Callable, Iterator
from typing import Any


class _Any:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __call__(self, *args: Any, **kwargs: Any) -> "_Any":
        return _Any()

    def __getattr__(self, name: str) -> "_Any":
        if name.startswith("__"):
            raise AttributeError(name)
        return _Any()

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __mro_entries__(self, bases: tuple[type, ...]) -> tuple[type, ...]:
        return (object,)

    def __int__(self) -> int: return 10
    def __float__(self) -> float: return 10.0
    def __index__(self) -> int: return 10
    def __bool__(self) -> bool: return True
    def __lt__(self, other: Any) -> bool: return False
    __le__ = __gt__ = __ge__ = __lt__

    def _op(self, *args: Any) -> "_Any":
        return _Any()

    __add__ = __radd__ = __sub__ = __rsub__ = __mul__ = __rmul__ = _op
    __truediv__ = __rtruediv__ = __floordiv__ = __rfloordiv__ = _op
    __mod__ = __neg__ = __or__ = _op


_C: dict[str, int] = {}
_ENUM_NAMES = {
    "AlignmentFlag", "ApplicationAttribute", "ApplicationState", "AspectRatioMode",
    "BrushStyle", "ContextMenuPolicy", "CursorShape", "FocusPolicy", "GlobalColor",
    "ItemDataRole", "Key", "KeyboardModifier", "MouseButton", "OpenModeFlag",
    "Orientation", "PenCapStyle", "PenJoinStyle", "PenStyle", "RenderHint",
    "ShortcutContext", "State", "TextFlag", "TextFormat", "TextInteractionFlag",
    "TransformationMode", "Type", "WindowFlags", "WindowState", "WindowType",
    "WidgetAttribute",
}
_ENUM_TYPES: dict[str, type] = {}


class _EnumMeta(type):
    def __getattr__(cls, name: str) -> int:
        if name.startswith("__"):
            raise AttributeError(name)
        return _C.setdefault(f"{cls.__name__}.{name}", len(_C) + 1)

    def __call__(cls, *args: Any, **kwargs: Any) -> "_Any":
        return _Any()


def _enum_type(name: str) -> type:
    enum_type = _ENUM_TYPES.get(name)
    if enum_type is None:
        enum_type = _EnumMeta(name, (), {})
        _ENUM_TYPES[name] = enum_type
    return enum_type


class _Meta(type):
    def __getattr__(cls, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        if name in _ENUM_NAMES:
            return _enum_type(name)
        if name[:1].isupper():
            return _C.setdefault(name, len(_C) + 1)  # enum-like constants are stable ints
        return _noop

    def __or__(cls, other: Any) -> type:
        return cls


def _noop(*args: Any, **kwargs: Any) -> None:
    pass


def _stub_init(self: Any, *args: Any, **kwargs: Any) -> None:
    pass


def _stub_getattr(self: Any, name: str) -> _Any:
    return _Any()


def _mk(name: str) -> type:
    return _Meta(name, (), {"__init__": _stub_init, "__getattr__": _stub_getattr})


class Mod(types.ModuleType):
    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        if name == "pyqtProperty":
            return _pyqt_property
        cls = _mk(name)
        setattr(self, name, cls)
        return cls


def _property_getter(instance: Any) -> None:
    return None


def _pyqt_property(*args: Any, **kwargs: Any) -> property:
    return property(_property_getter)


for module_name in ["PyQt5", "PyQt5.QtCore", "PyQt5.QtGui", "PyQt5.QtWidgets", "PyQt5.QtMultimedia", "PyQt5.QtMultimediaWidgets", "PyQt5.QtSvg"]:
    sys.modules[module_name] = Mod(module_name)


class QColor:
    r: int
    g: int
    b: int

    def __init__(self, *args: Any) -> None:
        if len(args) == 1 and isinstance(args[0], str):
            hex_color = args[0].lstrip("#")
            self.r = int(hex_color[0:2], 16)
            self.g = int(hex_color[2:4], 16)
            self.b = int(hex_color[4:6], 16)
        elif len(args) >= 3:
            self.r, self.g, self.b = int(args[0]), int(args[1]), int(args[2])
        elif len(args) == 1 and isinstance(args[0], QColor):
            self.r, self.g, self.b = args[0].r, args[0].g, args[0].b
        else:
            self.r = self.g = self.b = 0

    def red(self) -> int: return self.r
    def green(self) -> int: return self.g
    def blue(self) -> int: return self.b
    def name(self) -> str: return "#%02x%02x%02x" % (self.r, self.g, self.b)
    def lightness(self) -> int: return (max(self.r, self.g, self.b) + min(self.r, self.g, self.b)) // 2

    def __getattr__(self, name: str) -> Callable[..., None]:
        return _noop


setattr(sys.modules["PyQt5.QtGui"], "QColor", QColor)

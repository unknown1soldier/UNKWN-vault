"""Small, local-only Easter Egg message and temporary-theme helpers."""

from __future__ import annotations

import random
import sys
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from easter_egg_messages import (
    cancellation_messages,
    empty_search_messages,
    hidden_nothing_button_messages,
    loading_messages,
    warden_intro_messages,
)


SECRET_THEME_PHRASE = "!FUCK THIS SHIT"
SECRET_THEME_DURATION_MS = 20_000
SECRET_THEME_PALETTE = {
    "bg0": "#fff0f7",
    "bg1": "#f8d9eb",
    "field": "#fff8fc",
    "panel": "#fce9f3",
    "line": "#eda8ce",
    "fg": "#70234d",
    "mut": "#a45c83",
    "dim": "#bc83a0",
    "acc": "#ff69b4",
    "acc2": "#f5b5dc",
    "on": "#ffffff",
}
MESSAGE_COLLECTIONS: Mapping[str, tuple[str, ...]] = {
    "loading": loading_messages,
    "cancellation": cancellation_messages,
    "empty_search": empty_search_messages,
    "warden": warden_intro_messages,
    "hidden_nothing": hidden_nothing_button_messages,
}


@dataclass(frozen=True)
class ThemeSnapshot:
    profile_key: str
    theme_name: str
    palette: Mapping[str, str]


def resource_path(
    relative_path: str,
    *,
    module_file: Optional[Path] = None,
    executable_path: Optional[Path] = None,
    resource_roots: Optional[Sequence[Path]] = None,
) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Easter Egg resource paths must stay inside a resource root.")

    if resource_roots is None:
        module_location = Path(__file__ if module_file is None else module_file)
        executable = Path(sys.executable if executable_path is None else executable_path)
        roots = (module_location.resolve().parent, executable.resolve().parent)
    else:
        roots = tuple(Path(root).resolve() for root in resource_roots)

    checked: set[Path] = set()
    for root in roots:
        if root in checked:
            continue
        checked.add(root)
        candidate = root / relative
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(root / relative) for root in checked)
    raise FileNotFoundError(f"Required Easter Egg resource was not found. Searched: {searched}")


class MessagePool:
    """Thread-safe shuffled selection without repeats within or across pool cycles."""

    def __init__(self, messages: Sequence[str], recent_limit: int = 32) -> None:
        self.messages = tuple(messages)
        if not self.messages or any(not message.strip() for message in self.messages):
            raise ValueError("A message pool must contain only non-empty messages.")
        if len(set(self.messages)) != len(self.messages):
            raise ValueError("A message pool must contain distinct messages.")
        self._recent: deque[str] = deque(maxlen=min(recent_limit, len(self.messages) - 1))
        self._deck: list[str] = []
        self._position = 0
        self._lock = threading.Lock()

    def next(self) -> str:
        with self._lock:
            if self._position >= len(self._deck):
                self._deck = list(self.messages)
                random.SystemRandom().shuffle(self._deck)
                self._position = 0
            recent = set(self._recent)
            if self._deck[self._position] in recent:
                next_available = next(
                    (i for i in range(self._position + 1, len(self._deck))
                     if self._deck[i] not in recent),
                    None,
                )
                if next_available is not None:
                    self._deck[self._position], self._deck[next_available] = (
                        self._deck[next_available], self._deck[self._position])
            message = self._deck[self._position]
            self._position += 1
            self._recent.append(message)
            return message


class EasterEggs:
    def __init__(self) -> None:
        self._pools = {
            key: MessagePool(messages)
            for key, messages in MESSAGE_COLLECTIONS.items()
        }
        self._triggered_profiles: set[str] = set()
        self._active_themes: dict[str, ThemeSnapshot] = {}
        self._theme_lock = threading.Lock()

    def message(self, category: str) -> str:
        try:
            pool = self._pools[category]
        except KeyError as exc:
            raise ValueError(f"Unknown Easter Egg message category: {category}") from exc
        return pool.next()

    def activate_secret_theme(
        self,
        profile_key: str,
        query: str,
        theme_name: str,
        palette: Mapping[str, str],
    ) -> Optional[ThemeSnapshot]:
        if query != SECRET_THEME_PHRASE:
            return None
        if not profile_key:
            raise ValueError("A profile key is required for a temporary secret theme.")
        with self._theme_lock:
            if profile_key in self._triggered_profiles:
                return None
            self._triggered_profiles.add(profile_key)
            snapshot = ThemeSnapshot(profile_key, theme_name, dict(palette))
            self._active_themes[profile_key] = snapshot
            return snapshot

    def restore_secret_theme(self, profile_key: str) -> Optional[ThemeSnapshot]:
        with self._theme_lock:
            return self._active_themes.pop(profile_key, None)


EASTER_EGGS = EasterEggs()

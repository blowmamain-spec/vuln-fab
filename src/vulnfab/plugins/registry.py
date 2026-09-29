"""Plugin discovery and stack detection (WP-1.2).

Plugins come from the built-in list and from the ``vulnfab.plugins`` entry-point group.
A plugin is *active* when ``detect`` returns at least MEDIUM confidence, or when it is forced
with ``--stack``. LOW means "weak hint only" and does not activate it.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from importlib.metadata import entry_points

from vulnfab.core.models import Confidence
from vulnfab.plugins.base import RepoView, StackPlugin

ENTRY_POINT_GROUP = "vulnfab.plugins"
# "module:attribute" — the attribute is a plugin class or a ready instance.
BUILTIN_PLUGINS = (
    "vulnfab.plugins.generic:GenericPlugin",
    "vulnfab.plugins.django:DjangoPlugin",
    "vulnfab.plugins.laravel:LaravelPlugin",
    "vulnfab.plugins.supabase:SupabasePlugin",
    "vulnfab.plugins.typescript:TypeScriptPlugin",
)

ACTIVATION_THRESHOLD = Confidence.MEDIUM


class UnknownStackError(Exception):
    pass


@dataclass(frozen=True)
class Selected:
    plugin: StackPlugin
    confidence: Confidence
    forced: bool = False


def _instantiate(obj: object) -> StackPlugin:
    plugin = obj() if isinstance(obj, type) else obj
    if not isinstance(plugin, StackPlugin):
        raise TypeError(f"{obj!r} does not implement the StackPlugin protocol")
    return plugin


def discover() -> list[StackPlugin]:
    found: dict[str, StackPlugin] = {}
    for spec in BUILTIN_PLUGINS:
        module_name, _, attr = spec.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue  # built-in plugin not present yet
        plugin = _instantiate(getattr(module, attr))
        found[plugin.name] = plugin
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        plugin = _instantiate(ep.load())
        found.setdefault(plugin.name, plugin)
    return list(found.values())


def select(
    plugins: list[StackPlugin], repo: RepoView, forced: list[str] | None = None
) -> list[Selected]:
    by_name = {p.name: p for p in plugins}
    forced_names = list(dict.fromkeys(forced or []))
    unknown = [n for n in forced_names if n not in by_name]
    if unknown:
        known = ", ".join(sorted(by_name))
        raise UnknownStackError(f"unknown stack(s): {', '.join(unknown)} (available: {known})")
    selected: list[Selected] = []
    for plugin in plugins:
        confidence = plugin.detect(repo)
        is_forced = plugin.name in forced_names
        if is_forced or confidence.rank >= ACTIVATION_THRESHOLD.rank:
            selected.append(Selected(plugin, confidence, is_forced))
    if forced_names:
        # forcing stacks restricts the scan to those stacks (plus the language-level plugin)
        selected = [s for s in selected if s.forced or s.plugin.name == "generic"]
    return selected

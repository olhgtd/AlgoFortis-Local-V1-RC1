"""Internal-only adapter registry for AlgoFortis V2.0.

The registry is deliberately explicit: adapters are registered by trusted
application composition. It does not scan packages, import arbitrary modules,
or load third-party code dynamically.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Callable, Mapping


class AdapterRegistryError(ValueError):
    """Raised when registration or activation violates the registry contract."""


class AdapterKind(str, Enum):
    BROKER = "broker"
    DATA = "data"
    AI_PROVIDER = "ai_provider"
    NOTIFIER = "notifier"
    REPORT = "report"
    FEE_MODEL = "fee_model"
    SLIPPAGE_MODEL = "slippage_model"
    EXECUTION_MODEL = "execution_model"
    RISK_RULE = "risk_rule"
    INDICATOR = "indicator"
    STRATEGY = "strategy"


_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_CONTRACT_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)@(\d+)$")
_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|==)?(\d+)(?:\.(\d+))?(?:\.(\d+))?$")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterRegistryError(f"{field} must be a non-empty string")
    return value.strip()


def _semver(value: str, field: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(_text(value, field))
    if match is None:
        raise AdapterRegistryError(f"{field} must be semantic version MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _contract(value: str) -> tuple[str, int]:
    match = _CONTRACT_RE.fullmatch(_text(value, "contract"))
    if match is None:
        raise AdapterRegistryError("contract must use exact Name@integer-version form")
    return match.group(1), int(match.group(2))


def _unique_text_tuple(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise AdapterRegistryError(f"{field} must be a tuple")
    normalized = tuple(_text(item, field) for item in values)
    if len(set(normalized)) != len(normalized):
        raise AdapterRegistryError(f"duplicate {field} entries are not allowed")
    return normalized


def _compatible(core_version: tuple[int, int, int], expression: str) -> bool:
    expression = _text(expression, "compatible_core")
    clauses = [part.strip() for part in expression.split(",") if part.strip()]
    if not clauses:
        raise AdapterRegistryError("core compatibility expression must not be empty")

    for clause in clauses:
        match = _COMPARATOR_RE.fullmatch(clause)
        if match is None:
            raise AdapterRegistryError(f"unsupported core compatibility clause: {clause!r}")
        operator = match.group(1) or "=="
        version = (
            int(match.group(2)),
            int(match.group(3) or 0),
            int(match.group(4) or 0),
        )
        ok = {
            ">=": core_version >= version,
            "<=": core_version <= version,
            ">": core_version > version,
            "<": core_version < version,
            "==": core_version == version,
        }[operator]
        if not ok:
            return False
    return True


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    kind: AdapterKind
    version: str
    contract: str
    capabilities: tuple[str, ...]
    permissions: tuple[str, ...]
    compatible_core: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter_id", _text(self.adapter_id, "adapter_id"))
        if not isinstance(self.kind, AdapterKind):
            raise AdapterRegistryError("kind must be an AdapterKind")
        _semver(self.version, "version")
        _contract(self.contract)
        object.__setattr__(
            self,
            "capabilities",
            _unique_text_tuple(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self,
            "permissions",
            _unique_text_tuple(self.permissions, "permissions"),
        )
        object.__setattr__(self, "compatible_core", _text(self.compatible_core, "compatible_core"))
        _compatible((0, 0, 0), self.compatible_core)


AdapterFactory = Callable[[], object]


@dataclass(frozen=True)
class AdapterRegistration:
    manifest: AdapterManifest
    factory: AdapterFactory

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, AdapterManifest):
            raise TypeError("manifest must be an AdapterManifest")
        if not callable(self.factory):
            raise TypeError("factory must be callable")


@dataclass(frozen=True)
class AdapterActivation:
    manifest: AdapterManifest
    instance: object


@dataclass(frozen=True)
class AdapterRegistryAuditEvent:
    action: str
    adapter_id: str
    version: str | None
    previous_version: str | None
    contract: str | None
    capabilities: tuple[str, ...]
    permissions: tuple[str, ...]


AuditSink = Callable[[AdapterRegistryAuditEvent], None]


class InternalAdapterRegistry:
    """Deterministic, trusted in-process registry for V2.0 adapters."""

    def __init__(
        self,
        *,
        core_version: str,
        supported_contracts: Mapping[str, int],
        audit_sink: AuditSink,
    ) -> None:
        self._core_version_text = _text(core_version, "core_version")
        self._core_version = _semver(self._core_version_text, "core_version")
        if not isinstance(supported_contracts, Mapping):
            raise TypeError("supported_contracts must be a mapping")
        contracts: dict[str, int] = {}
        for name, version in supported_contracts.items():
            name = _text(name, "contract name")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise AdapterRegistryError("supported contract version must be a positive integer")
            contracts[name] = version
        if not callable(audit_sink):
            raise TypeError("audit_sink must be callable")
        self._supported_contracts = contracts
        self._audit_sink = audit_sink
        self._registrations: dict[tuple[str, str], AdapterRegistration] = {}
        self._active: dict[str, AdapterActivation] = {}
        self._history: dict[str, list[str]] = {}

    def register(self, registration: AdapterRegistration) -> None:
        if not isinstance(registration, AdapterRegistration):
            raise TypeError("registration must be an AdapterRegistration")
        key = (registration.manifest.adapter_id, registration.manifest.version)
        if key in self._registrations:
            raise AdapterRegistryError(
                f"duplicate adapter registration: {key[0]!r} version {key[1]!r}"
            )
        self._registrations[key] = registration

    def discover(
        self,
        *,
        kind: AdapterKind | None = None,
        capability: str | None = None,
    ) -> tuple[AdapterManifest, ...]:
        if kind is not None and not isinstance(kind, AdapterKind):
            raise TypeError("kind must be an AdapterKind or None")
        capability_text = _text(capability, "capability") if capability is not None else None
        manifests = [
            registration.manifest
            for registration in self._registrations.values()
            if (kind is None or registration.manifest.kind is kind)
            and (
                capability_text is None
                or capability_text in registration.manifest.capabilities
            )
        ]
        return tuple(sorted(manifests, key=lambda item: (item.adapter_id, _semver(item.version, "version"))))

    def active_manifest(self, adapter_id: str) -> AdapterManifest | None:
        adapter_id = _text(adapter_id, "adapter_id")
        activation = self._active.get(adapter_id)
        return activation.manifest if activation is not None else None

    def _registration(self, adapter_id: str, version: str) -> AdapterRegistration:
        adapter_id = _text(adapter_id, "adapter_id")
        _semver(version, "version")
        registration = self._registrations.get((adapter_id, version))
        if registration is None:
            raise AdapterRegistryError(
                f"unknown exact adapter registration: {adapter_id!r} version {version!r}"
            )
        return registration

    def _validate_compatibility(self, manifest: AdapterManifest) -> None:
        if not _compatible(self._core_version, manifest.compatible_core):
            raise AdapterRegistryError(
                f"core compatibility rejected {manifest.adapter_id!r} {manifest.version!r} "
                f"for core {self._core_version_text!r}"
            )
        contract_name, contract_version = _contract(manifest.contract)
        supported = self._supported_contracts.get(contract_name)
        if supported != contract_version:
            raise AdapterRegistryError(
                f"contract {manifest.contract!r} is not supported exactly; "
                f"configured {contract_name!r} version is {supported!r}"
            )

    def _audit(self, event: AdapterRegistryAuditEvent) -> None:
        try:
            self._audit_sink(event)
        except Exception as exc:
            raise AdapterRegistryError("adapter activation audit failed") from exc

    @staticmethod
    def _event(
        action: str,
        manifest: AdapterManifest | None,
        *,
        adapter_id: str,
        previous_version: str | None,
    ) -> AdapterRegistryAuditEvent:
        return AdapterRegistryAuditEvent(
            action=action,
            adapter_id=adapter_id,
            version=manifest.version if manifest is not None else None,
            previous_version=previous_version,
            contract=manifest.contract if manifest is not None else None,
            capabilities=manifest.capabilities if manifest is not None else (),
            permissions=manifest.permissions if manifest is not None else (),
        )

    def enable(self, adapter_id: str, version: str) -> AdapterActivation:
        registration = self._registration(adapter_id, version)
        manifest = registration.manifest
        self._validate_compatibility(manifest)
        previous = self._active.get(manifest.adapter_id)
        try:
            instance = registration.factory()
        except Exception as exc:
            raise AdapterRegistryError("adapter factory failed during enable") from exc
        activation = AdapterActivation(manifest=manifest, instance=instance)
        event = self._event(
            "ENABLE",
            manifest,
            adapter_id=manifest.adapter_id,
            previous_version=previous.manifest.version if previous is not None else None,
        )
        self._audit(event)
        if previous is not None:
            self._history.setdefault(manifest.adapter_id, []).append(previous.manifest.version)
        self._active[manifest.adapter_id] = activation
        return activation

    def disable(self, adapter_id: str) -> None:
        adapter_id = _text(adapter_id, "adapter_id")
        previous = self._active.get(adapter_id)
        if previous is None:
            raise AdapterRegistryError(f"unknown active adapter: {adapter_id!r}")
        event = self._event(
            "DISABLE",
            None,
            adapter_id=adapter_id,
            previous_version=previous.manifest.version,
        )
        self._audit(event)
        del self._active[adapter_id]

    def rollback(self, adapter_id: str) -> AdapterActivation:
        adapter_id = _text(adapter_id, "adapter_id")
        current = self._active.get(adapter_id)
        history = self._history.get(adapter_id, [])
        if current is None or not history:
            raise AdapterRegistryError(f"rollback unavailable for adapter {adapter_id!r}")
        target_version = history[-1]
        registration = self._registration(adapter_id, target_version)
        self._validate_compatibility(registration.manifest)
        try:
            instance = registration.factory()
        except Exception as exc:
            raise AdapterRegistryError("adapter factory failed during rollback") from exc
        activation = AdapterActivation(manifest=registration.manifest, instance=instance)
        event = self._event(
            "ROLLBACK",
            registration.manifest,
            adapter_id=adapter_id,
            previous_version=current.manifest.version,
        )
        self._audit(event)
        history.pop()
        self._active[adapter_id] = activation
        return activation

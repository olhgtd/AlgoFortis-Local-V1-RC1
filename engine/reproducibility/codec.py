"""D4 typed, length-delimited canonical fingerprint codec."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from typing import Iterable, Mapping, Sequence


class CanonicalEncodingError(ValueError):
    """Raised when evidence has no approved canonical representation."""


class CanonicalCodec:
    """Small explicit codec; callers own their schemas and field ordering."""

    schema_version = "sentinelx-canonical-codec/v1"

    @classmethod
    def fingerprint(cls, schema: str, fields: Sequence[tuple[str, object]]) -> str:
        return sha256(cls.encode_schema(schema, fields)).hexdigest()

    @classmethod
    def encode_schema(cls, schema: str, fields: Sequence[tuple[str, object]]) -> bytes:
        if not isinstance(schema, str) or not schema:
            raise CanonicalEncodingError("schema must be a non-empty string")
        names = tuple(name for name, _ in fields)
        if any(not isinstance(name, str) or not name for name in names):
            raise CanonicalEncodingError("field names must be non-empty strings")
        if len(names) != len(set(names)):
            raise CanonicalEncodingError("schema fields must be unique")
        return cls._record(
            "schema",
            (("codec_version", cls.schema_version), ("schema", schema), ("fields", tuple(fields))),
        )

    @classmethod
    def encode_value(cls, value: object) -> bytes:
        if value is None:
            return cls._atom("none", b"")
        if isinstance(value, bool):
            return cls._atom("bool", b"1" if value else b"0")
        if isinstance(value, int):
            return cls._atom("int", str(value).encode("ascii"))
        if isinstance(value, Decimal):
            return cls._atom("decimal", cls._decimal_text(value).encode("ascii"))
        if isinstance(value, str):
            return cls._atom("str", value.encode("utf-8"))
        if isinstance(value, bytes):
            return cls._atom("bytes", value)
        if isinstance(value, Enum):
            return cls._record(
                "enum",
                (("type", f"{type(value).__module__}.{type(value).__qualname__}"), ("member", value.name)),
            )
        if cls._is_pandas_timestamp(value):
            return cls._atom("timestamp", cls.timestamp_text(value).encode("ascii"))
        if isinstance(value, datetime):
            return cls._atom("timestamp", cls.timestamp_text(value).encode("ascii"))
        if isinstance(value, date):
            return cls._atom("date", value.isoformat().encode("ascii"))
        if isinstance(value, (tuple, list)):
            return cls._sequence(value)
        if isinstance(value, (set, frozenset)):
            raise CanonicalEncodingError("unordered sets require an owning schema ordering rule")
        if isinstance(value, Mapping):
            raise CanonicalEncodingError("mappings require explicit schema-defined field order")
        raise CanonicalEncodingError(f"unsupported canonical value type: {type(value).__name__}")

    @classmethod
    def timestamp_text(cls, value: object) -> str:
        if cls._is_pandas_timestamp(value):
            timestamp = value
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise CanonicalEncodingError("timestamp must be timezone-aware")
            try:
                nanoseconds = int(timestamp.tz_convert("UTC").value)
            except Exception as error:
                raise CanonicalEncodingError("timestamp cannot supply nanosecond precision") from error
            return cls._epoch_nanoseconds_text(nanoseconds)
        if not isinstance(value, datetime):
            raise CanonicalEncodingError("timestamp must be datetime-like")
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalEncodingError("timestamp must be timezone-aware")
        utc = value.astimezone(timezone.utc)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = utc - epoch
        nanoseconds = ((delta.days * 86_400 + delta.seconds) * 1_000_000_000) + delta.microseconds * 1_000
        return cls._epoch_nanoseconds_text(nanoseconds)

    @classmethod
    def _epoch_nanoseconds_text(cls, nanoseconds: int) -> str:
        seconds, fraction = divmod(nanoseconds, 1_000_000_000)
        try:
            instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        except OverflowError as error:
            raise CanonicalEncodingError("timestamp outside supported canonical range") from error
        return f"{instant:%Y-%m-%dT%H:%M:%S}.{fraction:09d}Z"

    @staticmethod
    def _is_pandas_timestamp(value: object) -> bool:
        try:
            import pandas as pd
        except ImportError:
            return False
        return isinstance(value, pd.Timestamp)

    @staticmethod
    def _decimal_text(value: Decimal) -> str:
        if not value.is_finite():
            raise CanonicalEncodingError("non-finite Decimal is not authoritative evidence")
        if value.is_zero():
            return "0"
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text

    @classmethod
    def _sequence(cls, values: Iterable[object]) -> bytes:
        encoded = tuple(cls.encode_value(value) for value in values)
        payload = cls._length(len(encoded).to_bytes(8, "big")) + b"".join(cls._length(value) for value in encoded)
        return cls._atom("sequence", payload)

    @classmethod
    def _record(cls, tag: str, fields: Sequence[tuple[str, object]]) -> bytes:
        pieces = []
        for name, value in fields:
            if not isinstance(name, str) or not name:
                raise CanonicalEncodingError("record field name must be non-empty")
            pieces.append(cls._length(name.encode("utf-8")) + cls._length(cls.encode_value(value)))
        return cls._atom(tag, b"".join(pieces))

    @staticmethod
    def _length(value: bytes) -> bytes:
        return len(value).to_bytes(8, "big") + value

    @classmethod
    def _atom(cls, tag: str, payload: bytes) -> bytes:
        return cls._length(tag.encode("ascii")) + cls._length(payload)

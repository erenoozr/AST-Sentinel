"""AST-Sentinel: static security and complexity analyzer for Python."""

__version__ = "1.0.0"

from .core import (  # noqa: E402  (__version__ must be defined first; the report module imports it)
    BaseRule,
    Finding,
    FunctionMetric,
    ScanContext,
    ScanResult,
    SecurityScanner,
    Severity,
)

__all__ = [
    "BaseRule",
    "Finding",
    "FunctionMetric",
    "ScanContext",
    "ScanResult",
    "SecurityScanner",
    "Severity",
    "__version__",
]

"""Default rule set."""
from .quality import ComplexityRule, UnusedLocalRule, UnusedPrivateFunctionRule
from .security import DangerousCallRule, HardcodedSecretRule, SQLInjectionRule, WeakCryptoRule

DEFAULT_RULES = (
    HardcodedSecretRule,
    DangerousCallRule,
    SQLInjectionRule,
    WeakCryptoRule,
    ComplexityRule,
    UnusedLocalRule,
    UnusedPrivateFunctionRule,
)

__all__ = [rule.__name__ for rule in DEFAULT_RULES] + ["DEFAULT_RULES"]

"""Deterministic fee calculation helper for sample release artifact discovery."""


def calculate_platform_fee(amount_cents: int, tier: str = "standard") -> int:
    rates = {"enterprise": 0.015, "team": 0.022, "standard": 0.029}
    rate = rates.get(tier, 0.029)
    return max(30, int(round(amount_cents * rate)))


if __name__ == "__main__":
    print(calculate_platform_fee(10000, "team"))

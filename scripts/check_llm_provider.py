"""Manual, non-test smoke check for an environment-configured compatible provider."""

from __future__ import annotations

import sys

from chipchain.reasoning import OpenAICompatibleLLMProvider


def main() -> int:
    """Send a minimal request without printing credentials or endpoint details."""

    try:
        provider = OpenAICompatibleLLMProvider.from_env()
        result = provider.check_connection()
        if result != "OK":
            raise RuntimeError("provider did not return the expected smoke-test token")
        print("Provider connection: OK")
        print(f"API style: {provider.config.api_style.value}")
        print(f"Model: {provider.config.model}")
        return 0
    except Exception as exc:
        print("Provider connection: FAILED")
        print(f"Error type: {type(exc).__name__}")
        status_code = getattr(exc, "status_code", None)
        print(f"Status code: {status_code if status_code is not None else 'unavailable'}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

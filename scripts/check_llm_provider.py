"""Manual, non-test smoke check for an environment-configured compatible provider."""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

from chipchain.reasoning import OpenAICompatibleLLMProvider


def main() -> int:
    """Send a minimal request without printing credentials or endpoint details."""

    try:
        project_root = Path(__file__).resolve().parents[1]
        load_dotenv(project_root / ".env", override=False)
        provider = OpenAICompatibleLLMProvider.from_env()
        result = provider.check_connection()
        if result != "OK":
            raise RuntimeError("provider did not return the expected smoke-test token")
        print("Provider connection: OK")
        print(f"API style: {provider.config.api_style.value}")
        print(f"Model: {provider.config.model}")
        print(
            "HTTP status: "
            f"{provider.last_http_status if provider.last_http_status is not None else 'unavailable'}"
        )
        return 0
    except Exception as exc:
        print("Provider connection: FAILED")
        print(f"Error type: {type(exc).__name__}")
        print(f"Error stage: {getattr(exc, 'stage', 'configuration')}")
        print(f"Error detail: {exc}")
        status_code = getattr(exc, "status_code", None)
        print(f"Status code: {status_code if status_code is not None else 'unavailable'}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

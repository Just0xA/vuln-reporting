"""
tenable_client.py — Authenticated TenableIO client factory.

Loads credentials exclusively from the .env file via python-dotenv.
Validates the connection on instantiation and exits with a clear error
message if authentication fails or environment variables are missing.

Usage:
    from tenable_client import get_client
    tio = get_client()
"""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv
from tenable.io import TenableIO
from tenable.errors import APIError, AuthenticationError

from config import LOG_LEVEL, LOG_DIR

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


def get_client() -> TenableIO:
    """
    Build and return an authenticated TenableIO client.

    Reads credentials from the .env file in the project root.  Exits the
    process with a non-zero status code and a human-readable error message
    if any required variable is missing or if the API rejects the credentials.

    Returns
    -------
    TenableIO
        A live, authenticated Tenable client ready for API calls.
    """
    load_dotenv()

    access_key = os.getenv("TVM_ACCESS_KEY")
    secret_key = os.getenv("TVM_SECRET_KEY")
    url = os.getenv("TVM_URL", "https://cloud.tenable.com")

    # ------------------------------------------------------------------
    # Validate that required variables are present
    # ------------------------------------------------------------------
    missing: list[str] = []
    if not access_key:
        missing.append("TVM_ACCESS_KEY")
    if not secret_key:
        missing.append("TVM_SECRET_KEY")

    if missing:
        logger.error(
            "Missing required environment variable(s): %s\n"
            "Copy .env.example to .env and fill in your Tenable API keys.",
            ", ".join(missing),
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # Build the client
    # ------------------------------------------------------------------
    try:
        tio = TenableIO(
            access_key=access_key,
            secret_key=secret_key,
            url=url,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to instantiate TenableIO client: %s", exc)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Validate the connection with a lightweight API call
    # ------------------------------------------------------------------
    try:
        _validate_connection(tio)
    except AuthenticationError:
        logger.error(
            "Tenable API authentication failed.\n"
            "Check that TVM_ACCESS_KEY and TVM_SECRET_KEY in your .env are correct\n"
            "and that the API key has sufficient permissions."
        )
        sys.exit(1)
    except APIError as exc:
        logger.error(
            "Tenable API returned an error during connection validation: %s", exc
        )
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Unexpected error while connecting to Tenable at %s: %s", url, exc
        )
        sys.exit(1)

    logger.info("Successfully authenticated to Tenable at %s", url)
    return tio


def _validate_connection(tio: TenableIO) -> None:
    """
    Perform a lightweight API call to confirm credentials are valid.

    Uses the server status endpoint which requires no special permissions
    and returns quickly regardless of data volume.

    Parameters
    ----------
    tio : TenableIO
        The client to validate.

    Raises
    ------
    AuthenticationError
        If the API rejects the credentials.
    APIError
        On any other non-200 response.
    """
    # tio.server.status() returns a small dict — fast and low-permission
    status = tio.server.status()
    logger.debug("Tenable server status: %s", status)


if __name__ == "__main__":
    # Quick connectivity test:  python tenable_client.py
    client = get_client()
    print("Connection successful. Client is ready.")

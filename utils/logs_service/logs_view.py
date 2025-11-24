import streamlit as st
import os
from pathlib import Path

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "sigscan.log"


class LogsCheck:
    @staticmethod
    def _get_param(name: str, default: str = "") -> str:
        """Safely get a query param as a string for both old/new Streamlit behaviors."""
        params = st.query_params
        value = params.get(name, default)

        # Depending on Streamlit version, this might be str or list[str]
        if isinstance(value, list):
            return value[0] if value else default
        return value

    @staticmethod
    def check_admin_auth() -> bool:
        """Very simple auth using ?token=... in the URL + secrets."""
        token = LogsCheck._get_param("token", "")

        expected = os.getenv("ADMIN_TOKEN", "")
        if not expected:
            st.warning("ADMIN_TOKEN not set in secrets; logs view is unprotected.")
            return True

        if token != expected:
            st.error("Not authorized.")
            return False

        return True

    @staticmethod
    def read_last_lines(path: Path, max_lines: int = 500) -> str:
        if not path.exists():
            return "Log file does not exist yet."

        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        return "".join(lines[-max_lines:])

    @staticmethod
    def show_logs_page():
        st.title("SigScan Logs (Admin)")
        st.caption("Showing last 500 lines from logs/sigscan.log")

        if st.button("🔄 Refresh"):
            st.rerun()

        log_text = LogsCheck.read_last_lines(LOG_FILE, max_lines=500)
        st.text_area(
            "Logs",
            value=log_text,
            height=500,
            label_visibility="collapsed",
        )

        # Optional: download button
        st.download_button(
            "⬇️ Download full log file",
            LOG_FILE.read_bytes() if LOG_FILE.exists() else b"No log file",
            file_name="sigscan.log",
        )

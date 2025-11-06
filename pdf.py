# pdf_decryptor.py
"""
Professional PDF Decryptor (Streamlit)
- main_page() is the entrypoint for the app.
- Supports single-password try, streamed wordlist attacks,
  optional simple word mangling (capitalization / common suffixes),
  accurate progress & ETA when wordlist line count is enabled,
  graceful cancellation, and download of decrypted PDF when found.

Notes:
- Use only on PDFs you own or have explicit permission to recover.
- Large wordlists may take time; counting lines scans the file once to produce an accurate ETA.
"""
from __future__ import annotations
import streamlit as st
import pikepdf
import io
import time
import math
from typing import Iterator, Optional, Iterable, List
from pikepdf import PasswordError, PdfError

# ---------- Constants & small helpers ----------
MAX_WORDLIST_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB safety cap for uploads (adjust if needed)
PROGRESS_UPDATE_SEC = 0.2  # UI throttle for updates to avoid UI spam
DEFAULT_MANGLE_SUFFIXES = ["", "!", "1", "123", "2023", "@"]


def _text_stream_from_fileobj(fileobj: io.BufferedIOBase, encoding: str = "utf-8"):
    """Return a generator yielding decoded lines from an uploaded file-like object."""
    fileobj.seek(0)
    wrapper = io.TextIOWrapper(fileobj, encoding=encoding, errors="ignore")
    try:
        for raw in wrapper:
            yield raw.rstrip("\r\n")
    finally:
        # detach to avoid closing underlying stream which Streamlit manages
        wrapper.detach()
        fileobj.seek(0)


def stream_passwords(fileobj: io.BufferedIOBase, mangling: bool = False,
                     mangles: Optional[List[str]] = None) -> Iterator[str]:
    """
    Yield candidate passwords from fileobj.
    If mangling is True, yield simple mangled variants for each line.
    This generator is memory-light.
    """
    if mangles is None:
        mangles = DEFAULT_MANGLE_SUFFIXES

    for line in _text_stream_from_fileobj(fileobj):
        pwd = line.strip()
        if not pwd:
            continue
        # base
        yield pwd
        if mangling:
            # simple mangles: capitalized, upper, suffixes
            yield pwd.capitalize()
            yield pwd.upper()
            for suf in mangles:
                if suf:
                    yield f"{pwd}{suf}"
                    yield f"{pwd.capitalize()}{suf}"
    # after iteration reset position
    fileobj.seek(0)


def count_lines(fileobj: io.BufferedIOBase) -> int:
    """Count lines in fileobj in a memory-efficient way; resets file pointer to 0."""
    fileobj.seek(0)
    wrapper = io.TextIOWrapper(fileobj, encoding="utf-8", errors="ignore")
    n = 0
    for _ in wrapper:
        n += 1
    wrapper.detach()
    fileobj.seek(0)
    return n


def try_open_pdf_return_bytes(pdf_bytes: bytes, password: str) -> Optional[bytes]:
    """
    Attempt to open PDF bytes with `password`.
    If successful, return bytes of a decrypted copy. If password wrong, return None.
    Raise PdfError for other PDF issues.
    """
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes), password=password) as pdf:
            out = io.BytesIO()
            pdf.save(out)
            out.seek(0)
            return out.read()
    except PasswordError:
        return None
    except PdfError:
        raise


# ---------- Main UI Entrypoint ----------
def main_page():
    st.set_page_config(page_title="PDF Decryptor", layout="wide", initial_sidebar_state="expanded")
    st.title("🔐 Professional PDF Decryptor")
    st.markdown(
        "Recover an *open* password for PDFs using a known password or a streamed wordlist attack. "
        "**Only use on files you own or have explicit permission to recover.**"
    )

    # Sidebar: global controls
    with st.sidebar:
        st.header("Options")
        enable_mangling = st.checkbox("Enable simple word mangling (capitalize / suffixes)", value=False)
        mangling_suffixes = st.text_input(
            "Comma-separated suffixes for mangling (example: !,1,123)",
            value=",".join(DEFAULT_MANGLE_SUFFIXES[1:])  # skip empty default
        )
        show_current = st.checkbox("Show current candidate in log (verbose)", value=False)
        count_lines_for_eta = st.checkbox("Count lines first for accurate ETA", value=True)
        max_attempts = st.number_input("Maximum attempts (0 = no limit)", min_value=0, value=0, step=1000)
        st.markdown("---")
        st.caption("Line counting scans the wordlist once to compute ETA. "
                   "Large wordlists may take noticeable time to count.")

    # Main layout: uploader and controls
    left, right = st.columns([1.2, 1])

    with left:
        pdf_file = st.file_uploader("Upload PDF file", type=["pdf"], help="Select the protected PDF.")
        if pdf_file is not None:
            size = pdf_file.size
            st.caption(f"PDF size: {size / 1024:.1f} KB")
            if size > 50 * 1024 * 1024:
                st.warning("Large PDF — operations may take longer.")

        known_password = st.text_input("Try a single known password (fast)", type="password")
        try_single_btn = st.button("Try single password")

    with right:
        wordlist_file = st.file_uploader("Upload wordlist (.txt, one password per line)", type=["txt"],
                                         help="Plain text file. For large lists, enable counting for ETA.")
        if wordlist_file is not None and wordlist_file.size > MAX_WORDLIST_SIZE_BYTES:
            st.error("Uploaded wordlist exceeds the safety cap. Use a smaller file or increase the cap in code.")
        start_attack_btn = st.button("Start wordlist attack")
        stop_attack_btn = st.button("Stop / Cancel attack", key="stop_attack")

    # Area for status/log/progress
    status = st.empty()
    progress_bar = st.empty()
    log_area = st.empty()

    # persistent session state for cancellation and progress
    if "attack_state" not in st.session_state:
        st.session_state.attack_state = {
            "running": False,
            "stop": False,
            "attempts": 0,
            "found": False,
            "last_update": 0.0,
        }

    # Helper to reset attack state
    def reset_attack_state():
        st.session_state.attack_state.update({
            "running": False,
            "stop": False,
            "attempts": 0,
            "found": False,
            "last_update": 0.0,
        })

    # Single password try
    if try_single_btn:
        reset_attack_state()
        if not pdf_file:
            st.warning("Please upload a PDF first.")
        elif not known_password:
            st.info("Enter a password to try.")
        else:
            try:
                pdf_bytes = pdf_file.read()
                result = try_open_pdf_return_bytes(pdf_bytes, known_password)
                if result is not None:
                    status.success("✅ Password correct — PDF decrypted.")
                    st.download_button("Download decrypted PDF", data=result,
                                       file_name="decrypted.pdf", mime="application/pdf")
                else:
                    status.error("❌ Password incorrect.")
            except PdfError as e:
                status.error(f"PDF error: {e}")
            except Exception as e:
                status.error(f"Unexpected error: {e}")

    # Stop button handling
    if stop_attack_btn:
        st.session_state.attack_state["stop"] = True
        status.info("Stopping attack...")

    # Wordlist attack
    if start_attack_btn and not st.session_state.attack_state["running"]:
        reset_attack_state()
        if not pdf_file:
            st.warning("Please upload a PDF first.")
        elif not wordlist_file:
            st.warning("Please upload a wordlist first.")
        else:
            # prepare mangling suffix list
            suffix_list = [s.strip() for s in mangling_suffixes.split(",") if s.strip()] if enable_mangling else None

            # optional line count for ETA
            total_lines = None
            if count_lines_for_eta:
                with st.spinner("Counting lines in wordlist for ETA..."):
                    try:
                        total_lines = count_lines(wordlist_file)
                        st.info(f"Wordlist lines: {total_lines:,}")
                    except Exception as e:
                        st.warning(f"Could not count lines: {e}; proceeding without ETA.")
                        total_lines = None

            # read pdf bytes once
            try:
                pdf_bytes = pdf_file.read()
            except Exception as e:
                status.error(f"Failed to read PDF bytes: {e}")
                pdf_bytes = None

            if not pdf_bytes:
                status.error("Could not load PDF data.")
            else:
                # mark running
                st.session_state.attack_state["running"] = True
                st.session_state.attack_state["stop"] = False
                st.session_state.attack_state["attempts"] = 0
                st.session_state.attack_state["found"] = False
                start_time = time.time()
                last_ui_update = 0.0
                decrypted_bytes = None

                # Create generator for candidates
                candidates: Iterable[str] = stream_passwords(
                    wordlist_file,
                    mangling=enable_mangling,
                    mangles=suffix_list
                )

                # If max_attempts set (>0) we will stop after that many tries
                max_att = int(max_attempts) if max_attempts and max_attempts > 0 else None

                try:
                    for candidate in candidates:
                        if st.session_state.attack_state["stop"]:
                            status.warning("Attack cancelled by user.")
                            break

                        st.session_state.attack_state["attempts"] += 1
                        attempt_num = st.session_state.attack_state["attempts"]

                        # Apply attempt cap
                        if max_att is not None and attempt_num > max_att:
                            status.warning(f"Reached maximum attempts limit ({max_att}). Stopping.")
                            break

                        # Attempt open
                        try:
                            candidate_result = try_open_pdf_return_bytes(pdf_bytes, candidate)
                        except PdfError as e:
                            status.error(f"PDF error encountered: {e}")
                            break  # unrecoverable PDF error

                        # Update logging / verbose as throttled
                        now = time.time()
                        if show_current and (now - last_ui_update > PROGRESS_UPDATE_SEC):
                            log_area.info(f"Trying #{attempt_num}: {candidate}")
                            last_ui_update = now
                        elif not show_current and (now - last_ui_update > 1.0):
                            log_area.info(f"Attempts: {attempt_num:,}")
                            last_ui_update = now

                        # If found, present download
                        if candidate_result is not None:
                            st.session_state.attack_state["found"] = True
                            decrypted_bytes = candidate_result
                            elapsed = now - start_time
                            status.success(f"✅ Password found after {attempt_num:,} attempts ({elapsed:.1f}s).")
                            st.download_button("Download decrypted PDF", data=decrypted_bytes,
                                               file_name="decrypted.pdf", mime="application/pdf")
                            break

                        # Progress & ETA update if we have total_lines (note: mangling can increase attempts)
                        if total_lines:
                            # Note: with mangling the true total attempts > total_lines; show progress by base-lines tried
                            base_progress = min(attempt_num / total_lines, 1.0)
                            progress_bar.progress(base_progress)
                            # ETA estimate (simple linear extrapolation)
                            elapsed = now - start_time
                            if attempt_num > 0:
                                est_total = (elapsed / attempt_num) * (total_lines)
                                eta_seconds = max(0.0, est_total - elapsed)
                                eta_text = f"ETA: {int(eta_seconds)}s"
                            else:
                                eta_text = ""
                            status.info(f"Trying... Attempts: {attempt_num:,} — {eta_text}")
                        else:
                            # show activity indicator without true ETA
                            progress_bar.progress(min((attempt_num % 100) / 100.0, 1.0))
                            status.info(f"Trying... Attempts: {attempt_num:,}")

                    # End loop
                    if not st.session_state.attack_state["found"] and not st.session_state.attack_state["stop"]:
                        status.warning("Finished wordlist: no password found.")
                except Exception as e:
                    status.error(f"Unhandled exception during attack: {e}")
                finally:
                    st.session_state.attack_state["running"] = False

    # Footer / explanations
    st.markdown("---")
    st.markdown(
        "**How it works (short):**\n\n"
        "- If you provide a **single password**, the app tries it immediately and returns the decrypted file if correct.\n"
        "- If you provide a **wordlist**, the app streams the list and attempts each item. If you enable mangling, the app also tries simple variants (capitalization and suffixes) to increase chances.\n\n"
        "**Ethics & legality:** Only use this tool on files you own or have explicit permission to recover. "
        "Attempting to break protection on someone else's files may be illegal."
    )


if __name__ == "__main__":
    main_page()

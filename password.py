import streamlit as st
import string
import secrets
import math
import pyperclip

def passwordgen_page():
    """
    Professional password generator page.
    Strength is determined by entropy (internally) to avoid
    misleading labels on single-class passwords (e.g., numbers only).
    """
    st.title("🔐 Secure Password Generator")
    st.markdown(
        "Generate cryptographically-random passwords. Strength is computed "
        "from the actual character set and length (robust & predictable)."
    )
    st.divider()

    # Settings
    col1, col2 = st.columns(2)
    with col1:
        length = st.slider("Password length", 4, 64, 16)
    with col2:
        num_passwords = st.number_input("How many", min_value=1, max_value=12, value=1)

    st.markdown("**Include characters:**")
    c1, c2, c3, c4 = st.columns(4)
    use_uppercase = c1.checkbox("Uppercase (A–Z)", value=True)
    use_lowercase = c2.checkbox("Lowercase (a–z)", value=True)
    use_digits = c3.checkbox("Numbers (0–9)", value=True)
    use_symbols = c4.checkbox("Symbols (!@#$...)", value=True)

    avoid_ambiguous = st.checkbox("Avoid ambiguous characters (l, I, 1, O, 0)", value=False)
    enforce_policy = st.checkbox("Ensure each selected set appears at least once", value=True)

    # Build character pool exactly from user choices (no surprises)
    def build_char_pool():
        pool = ""
        if use_uppercase:
            pool += string.ascii_uppercase
        if use_lowercase:
            pool += string.ascii_lowercase
        if use_digits:
            pool += string.digits
        if use_symbols:
            pool += string.punctuation
        if avoid_ambiguous:
            for ch in "lI1O0":
                pool = pool.replace(ch, "")
        return pool

    char_pool = build_char_pool()
    if not char_pool:
        st.error("Please select at least one character class.")
        return

    # Entropy-based strength (internal). We don't display the number unless needed.
    def compute_entropy_bits(charset_size, length):
        # entropy = log2(charset_size ^ length) = length * log2(charset_size)
        if charset_size <= 0 or length <= 0:
            return 0.0
        return length * math.log2(charset_size)

    def entropy_to_label(entropy_bits):
        # Conservative thresholds (common guidance):
        # < 28 bits   -> Very Weak
        # 28 - 35     -> Weak
        # 36 - 59     -> Fair
        # 60 - 127    -> Strong
        # >=128       -> Very Strong
        if entropy_bits < 28:
            return 0, "Very Weak"
        if entropy_bits < 36:
            return 1, "Weak"
        if entropy_bits < 60:
            return 2, "Fair"
        if entropy_bits < 128:
            return 3, "Strong"
        return 4, "Very Strong"

    def generate_one_password(length, pool, enforce_policy):
        # If enforce_policy, ensure the generated password contains at least
        # one char from each selected class. Loop until satisfied (fast).
        while True:
            pwd = ''.join(secrets.choice(pool) for _ in range(length))
            if not enforce_policy:
                return pwd

            # policy checks
            if use_uppercase and not any(c.isupper() for c in pwd):
                continue
            if use_lowercase and not any(c.islower() for c in pwd):
                continue
            if use_digits and not any(c.isdigit() for c in pwd):
                continue
            if use_symbols and not any(c in string.punctuation for c in pwd):
                continue
            return pwd

    # Generate button
    if st.button("⚡ Generate Passwords", use_container_width=True):
        st.success("✅ Generated")
        st.divider()

        charset_size = len(char_pool)

        for idx in range(1, num_passwords + 1):
            pwd = generate_one_password(length, char_pool, enforce_policy)

            # Calculate entropy internally
            entropy_bits = compute_entropy_bits(charset_size, length)
            score_idx, label = entropy_to_label(entropy_bits)

            # Visual strength mapping
            strength_colors = ["#e63946", "#f4a261", "#f6bd60", "#90be6d", "#2a9d8f"]
            strength_percent = (score_idx + 1) * 20  # for progress bar

            # Output section
            st.markdown(f"### 🔑 Password #{idx}")
            st.code(pwd, language="text")

            col_left, col_right = st.columns([3, 1])
            with col_left:
                st.markdown(
                    f"**Strength:** <span style='color:{strength_colors[score_idx]};"
                    f" font-weight:bold;'>{label}</span>",
                    unsafe_allow_html=True,
                )

                # Give actionable guidance if weak
                if score_idx <= 1:
                    st.warning(
                        "This password is weak for real-world use. "
                        "Choose a longer password or include more character classes (uppercase, lowercase, digits, symbols)."
                    )
                else:
                    st.info("This password meets recommended strength for many uses.")
            with col_right:
                if st.button(f"📋 Copy #{idx}", key=f"copy_{idx}"):
                    pyperclip.copy(pwd)
                    st.toast(f"Password #{idx} copied", icon="✅")

            st.progress(strength_percent)
            st.divider()

        # Optional: show a short explanation of what we used to rate strength
        st.caption(
            "Strength is computed from the actual character set size × length (entropy). "
            "This prevents misleading labels on single-class passwords like numbers-only."
        )

# Run standalone
if __name__ == "__main__":
    passwordgen_page()

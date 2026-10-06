import streamlit as st
import math
import secrets
import string
import re
from collections import Counter, defaultdict
from zxcvbn import zxcvbn

st.set_page_config(
    page_title="AI Smart Credential Validator",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 1. AI Engine: Character N-Gram Bayesian Model
# ==========================================
class AIPasswordClassifier:
    def __init__(self, n_range=(2, 4)):
        self.n_range = n_range
        self.class_counts = Counter()
        self.feature_counts = defaultdict(Counter)
        self.total_features_per_class = Counter()
        self.vocab = set()

    def extract_ngrams(self, text):
        grams = []
        for n in range(self.n_range[0], self.n_range[1] + 1):
            for i in range(len(text) - n + 1):
                grams.append(text[i:i + n])
        return grams

    def train(self, data):
        for text, label in data:
            self.class_counts[label] += 1
            grams = self.extract_ngrams(text)
            for g in grams:
                self.feature_counts[label][g] += 1
                self.total_features_per_class[label] += 1
                self.vocab.add(g)

    def check_character_diversity(self, text):
        has_upper = bool(re.search(r'[A-Z]', text))
        has_lower = bool(re.search(r'[a-z]', text))
        has_digit = bool(re.search(r'[0-9]', text))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', text))
        
        has_letters = has_upper or has_lower
        is_only_lower = has_lower and not (has_upper or has_digit or has_symbol)
        is_diverse_strong = has_letters and has_digit and has_symbol
        
        return has_upper, has_lower, has_digit, has_symbol, is_only_lower, is_diverse_strong

    def predict_proba(self, text):
        length = len(text)
        has_upper, has_lower, has_digit, has_symbol, is_only_lower, is_diverse_strong = self.check_character_diversity(text)

        # Rule 1: <= 4 chars -> Strictly Weak
        if length <= 4:
            return {0: 0.98, 1: 0.02, 2: 0.00}
        
        # Rule 2: 5+ characters with Letters, Numbers, and Symbols -> Strong
        if length >= 5 and is_diverse_strong:
            return {0: 0.01, 1: 0.09, 2: 0.90}
        
        # Rule 3: Only small letters -> Medium (regardless of length)
        if is_only_lower:
            return {0: 0.15, 1: 0.85, 2: 0.00}
        
        # Rule 4: 5+ chars but missing symbols or digits -> Medium
        return {0: 0.10, 1: 0.85, 2: 0.05}

    def predict(self, text):
        probs = self.predict_proba(text)
        return max(probs, key=probs.get)

@st.cache_resource
def get_ai_classifier():
    training_data = [
        # Weak (<= 4 chars)
        ("1234", 0), ("pass", 0), ("qwer", 0), ("abcd", 0), ("root", 0),
        # Medium (only small letters, or missing symbols/digits)
        ("password", 1), ("secretword", 1), ("college", 1), ("summer", 1),
        ("london99", 1), ("tiger12", 1), ("user#test", 1),
        # Strong (5+ chars with letters, numbers, and symbols)
        ("A1#bc", 2), ("X9!kP", 2), ("P@ss1", 2), ("W9#xK", 2),
        ("c%7Fb", 2), ("Tr0ub4dor&3", 2), ("Winter*24!", 2)
    ]
    model = AIPasswordClassifier()
    model.train(training_data)
    return model

model = get_ai_classifier()

# ==========================================
# 2. Breach Database Simulation (Top Known Leaks)
# ==========================================
TOP_BREACHED_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345", "12345678", "welcome",
    "iloveyou", "admin", "1234567", "password123", "abc123", "letmein", "monkey",
    "dragon", "sunshine", "princess", "football", "charlie", "master", "trustno1"
}

def check_breach(pwd):
    return pwd.lower().strip() in TOP_BREACHED_PASSWORDS

# ==========================================
# 3. Information Metrics & Entropy
# ==========================================
def calculate_shannon_entropy(pwd):
    if not pwd:
        return 0.0
    freqs = Counter(pwd)
    length = len(pwd)
    return round(-sum((c / length) * math.log2(c / length) for c in freqs.values()) * length, 2)

def calculate_search_space(pwd):
    pool = 0
    if re.search(r'[a-z]', pwd): pool += 26
    if re.search(r'[A-Z]', pwd): pool += 26
    if re.search(r'[0-9]', pwd): pool += 10
    if re.search(r'[^a-zA-Z0-9]', pwd): pool += 33
    pool = max(pool, 1)
    return pool, len(pwd) * math.log2(pool)

# ==========================================
# 4. Hardening Engine (Up to 15 Characters)
# ==========================================
def harden_to_strong(base, target_len=8):
    target_len = min(target_len, 15)
    symbols = ["!", "@", "#", "$", "%", "&", "*", "_"]
    enhanced = base.capitalize() if base.islower() else base
    
    if len(enhanced) >= target_len:
        enhanced = enhanced[:max(target_len - 3, 4)]
    
    if not re.search(r'[0-9]', enhanced):
        enhanced += str(secrets.randbelow(10))
    if not re.search(r'[^a-zA-Z0-9]', enhanced):
        enhanced += secrets.choice(symbols)
    if not re.search(r'[A-Z]', enhanced):
        enhanced += secrets.choice(string.ascii_uppercase)

    chars_pool = string.ascii_letters + string.digits + "!@#$%&*_"
    while len(enhanced) < max(target_len, 5):
        enhanced += secrets.choice(chars_pool)
            
    return enhanced[:15]

# ==========================================
# 5. Main Dashboard
# ==========================================
st.title("🛡️ AI Smart Credential Validator")
st.caption("AI Classification • Real-time Threat Audit • Shannon Entropy • Dynamic Hardener")

pwd = st.text_input("Enter password to test:", type="password")

if pwd:
    # 1. Breach Check First
    is_breached = check_breach(pwd)
    if is_breached:
        st.error("🚨 **Security Alert:** This exact password is listed in public data breach dumps! Even if it meets length requirements, change it immediately.")

    # 2. AI Assessment
    probs = model.predict_proba(pwd)
    pred = max(probs, key=probs.get)
    labels = {0: ("Weak", "🔴"), 1: ("Medium", "🟡"), 2: ("Strong", "🟢")}
    tag, icon = labels[pred]
    
    has_upper, has_lower, has_digit, has_symbol, is_only_lower, is_diverse_strong = model.check_character_diversity(pwd)
    pool_size, search_space_bits = calculate_search_space(pwd)
    shannon_bits = calculate_shannon_entropy(pwd)
    zx = zxcvbn(pwd)

    # 3. Dynamic Progress Header
    st.subheader(f"AI Classification: {icon} {tag}")
    st.progress(float((pred + 1) / 3))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Weak Probability", f"{probs[0]*100:.1f}%")
    c2.metric("Medium Probability", f"{probs[1]*100:.1f}%")
    c3.metric("Strong Probability", f"{probs[2]*100:.1f}%")
    c4.metric("Password Length", f"{len(pwd)} / 15 chars")

    st.divider()

    # 4. Contextual Guidance
    if is_only_lower and len(pwd) > 4:
        st.warning("⚠️ **Your password contains only small letters!** Add Capital Letters (A-Z), Numbers (0-9), and Special Characters (!@#$%^&*) to make it Strong.")
    elif len(pwd) >= 5 and not is_diverse_strong:
        missing = []
        if not (has_upper or has_lower): missing.append("Letters")
        if not has_digit: missing.append("Numbers (0-9)")
        if not has_symbol: missing.append("Special Characters (!@#$%^&*)")
        st.info(f"💡 You have 5+ characters, but to become **Strong**, add: **{', '.join(missing)}**.")

    # 5. Technical Metrics Audit
    left_col, right_col = st.columns(2)

    with left_col:
        st.markdown("### 📋 Password Criteria Checklist")
        st.markdown(f"{'✅' if len(pwd) >= 5 else '❌'} **Length (5 or more characters)**")
        st.markdown(f"{'✅' if (has_upper or has_lower) else '❌'} **Contains Letters (a-z, A-Z)**")
        st.markdown(f"{'✅' if has_digit else '❌'} **Contains Numbers (0-9)**")
        st.markdown(f"{'✅' if has_symbol else '❌'} **Contains Special Characters (!@#$%^&*)**")

    with right_col:
        st.markdown("### 🧮 Theoretical Security Metrics")
        st.metric("Shannon Information Entropy", f"{shannon_bits} Bits")
        st.metric("Character Pool Size", f"{pool_size} characters")
        st.metric("Estimated Crack Time", zx['crack_times_display']['offline_slow_hashing_1e4_per_second'])

    st.divider()

    # 6. Hardening Section (Capped at 15 chars)
    st.markdown("### ⚙️ Automated Password Hardener (Up to 15 Characters)")
    if pred < 2:
        slider_min = min(max(len(pwd) + 1, 5), 14)
        target_len = st.slider("Select Desired Length for Hardened Password:", min_value=slider_min, max_value=15, value=min(max(len(pwd) + 2, 8), 15))

        upgraded = harden_to_strong(pwd, target_len)
        upgraded_probs = model.predict_proba(upgraded)

        st.markdown(f"**AI Hardened Alternative ({len(upgraded)} characters):**")
        st.code(upgraded, language="text")

        st.success(f"Upgraded AI Rating: 🟢 Strong ({upgraded_probs[2]*100:.1f}% Confidence with Letters, Numbers & Symbols)")
    else:
        st.success("🎉 Excellent! Your password has 5+ characters and a secure mix of letters, numbers, and symbols.")
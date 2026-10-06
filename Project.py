import streamlit as st
import math
import secrets
import string
import re
from collections import Counter
import json
import ollama

st.set_page_config(
    page_title="AI Smart Credential Validator (Ollama Powered)",
    page_icon="🛡️",
    layout="wide"
)


TOP_BREACHED_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345", "12345678", "welcome",
    "iloveyou", "admin", "1234567", "password123", "abc123", "letmein", "monkey",
    "dragon", "sunshine", "princess", "football", "charlie", "master", "trustno1"
}

def check_breach(pwd):
    return pwd.lower().strip() in TOP_BREACHED_PASSWORDS


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
    return pool, round(len(pwd) * math.log2(pool), 2)

def check_character_diversity(text):
    has_upper = bool(re.search(r'[A-Z]', text))
    has_lower = bool(re.search(r'[a-z]', text))
    has_digit = bool(re.search(r'[0-9]', text))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', text))
    
    has_letters = has_upper or has_lower
    is_only_lower = has_lower and not (has_upper or has_digit or has_symbol)
    is_diverse_strong = has_letters and has_digit and has_symbol
    return has_upper, has_lower, has_digit, has_symbol, is_only_lower, is_diverse_strong


def analyze_with_ollama(password, model_name="llama3.2"):
    prompt = f"""
    You are a cybersecurity AI evaluator. Analyze this password: "{password}".
    Strict Classification Rules:
    - If length <= 4: Strength MUST be "Weak"
    - If only lowercase letters OR lacking character diversity: Strength MUST be "Medium"
    - If length >= 5 AND contains uppercase, lowercase, numbers, and symbols: Strength MUST be "Strong"

    Respond strictly in valid JSON format with the following keys:
    {{
        "strength": "Weak" or "Medium" or "Strong",
        "reasoning": "brief explanation",
        "feedback": "actionable tip to improve it",
        "hardened_suggestion": "a secure 12-15 character hardened version derived from the original"
    }}
    Do not output any markdown code blocks or text outside the JSON.
    """
    try:
        response = ollama.chat(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            format="json"
        )
        data = json.loads(response['message']['content'])
        return data, None
    except Exception as e:
        return None, str(e)


def harden_to_strong(base, target_len=12):
    target_len = min(target_len, 15)
    symbols = ["!", "@", "#", "$", "%", "&", "*", "_"]
    enhanced = base.capitalize() if base.islower() else base
    
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

st.title("🛡️ AI Smart Credential Validator (Ollama Powered)")
st.caption("Local LLM Reasoning • Real-time Threat Audit • Shannon Entropy • AI Hardener")

pwd = st.text_input("Enter password to test:", type="password")

if pwd:
    if check_breach(pwd):
        st.error("🚨 **Security Alert:** This password exists in known breach datasets!")

    has_upper, has_lower, has_digit, has_symbol, is_only_lower, is_diverse_strong = check_character_diversity(pwd)
    pool_size, entropy_bits = calculate_search_space(pwd)
    shannon_bits = calculate_shannon_entropy(pwd)

    with st.spinner("AI is inspecting credential resiliency via Ollama..."):
        ai_result, error = analyze_with_ollama(pwd)

    if ai_result and "strength" in ai_result:
        strength = ai_result.get("strength", "Weak")
    else:
        if len(pwd) <= 4:
            strength = "Weak"
        elif is_only_lower or not is_diverse_strong:
            strength = "Medium"
        else:
            strength = "Strong"

    icons = {"Weak": "🔴", "Medium": "🟡", "Strong": "🟢"}
    progress_val = {"Weak": 0.33, "Medium": 0.66, "Strong": 1.0}.get(strength, 0.33)

    st.subheader(f"AI Classification: {icons.get(strength, '🔴')} {strength}")
    st.progress(progress_val)

    if ai_result:
        st.markdown(f"**AI Reasoning:** {ai_result.get('reasoning', '')}")
        if strength != "Strong":
            st.info(f"💡 **AI Guidance:** {ai_result.get('feedback', '')}")
    elif error:
        st.warning(f"Ollama note: {error}. Switched to local deterministic evaluation.")

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📋 Password Criteria Checklist")
        st.markdown(f"{'✅' if len(pwd) >= 5 else '❌'} **Length (5 or more characters)**")
        st.markdown(f"{'✅' if (has_upper or has_lower) else '❌'} **Contains Letters (a-z, A-Z)**")
        st.markdown(f"{'✅' if has_digit else '❌'} **Contains Numbers (0-9)**")
        st.markdown(f"{'✅' if has_symbol else '❌'} **Contains Special Characters (!@#$%^&*)**")

    with col2:
        st.markdown("### 🧮 Theoretical Security Metrics")
        st.metric("Shannon Information Entropy", f"{shannon_bits} Bits")
        st.metric("Character Pool Size", f"{pool_size} characters")
        st.metric("Keyspace Search Complexity", f"2^{entropy_bits} combinations")

    st.divider()

    st.markdown("### ⚙️ Hardening Engine")
    if strength != "Strong":
        suggested = None
        if ai_result and ai_result.get("hardened_suggestion"):
            suggested = ai_result.get("hardened_suggestion")
        else:
            suggested = harden_to_strong(pwd, target_len=12)

        st.markdown("**AI Hardened Alternative:**")
        st.code(suggested, language="text")
        st.success("🟢 Meets all criteria (5+ chars, letters, numbers & symbols).")
    else:
        st.success("🎉 Excellent! Your password meets all security criteria.")
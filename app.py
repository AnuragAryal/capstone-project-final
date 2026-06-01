import streamlit as st
import pandas as pd
import re
import time
import requests
import joblib
import io
import os
import imaplib
import email
import tempfile
from email.header import decode_header
from google import genai
from fpdf import FPDF
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup

# ==========================================
# CONFIGURATION & MODEL INITIALIZATION
# ==========================================
DEFAULT_GEMINI_KEY = "" 
DEFAULT_VT_KEY = "" 
MODEL_PATH = "haepd_metadata_v2_optimized.pkl"

@st.cache_resource
def load_structural_model():
    """Safely loads Sweeti's updated pkl model file."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            st.sidebar.error(f"⚠️ Model Load Error: {e}. Using fallback mode.")
            return None
    return None

structural_pipeline = load_structural_model()
# ==========================================

# --- 1. MAILBOX EXPLORER MODULE ---
def list_recent_emails(username, password, imap_server="imap.gmail.com"):
    """Fetches subjects of the last 10 emails for user selection."""
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        mail.select("inbox")
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()[-10:] 
        email_list = []
        for e_id in reversed(email_ids):
            status, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes): subject = subject.decode(encoding if encoding else "utf-8")
                    email_list.append({"id": e_id, "subject": subject})
        mail.logout()
        return email_list
    except Exception as e: return [{"id": None, "subject": f"Error: {str(e)}"}]

def fetch_specific_email(username, password, email_id, imap_server="imap.gmail.com"):
    """Fetches and CLEANS the email body, removing HTML/page code."""
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        mail.select("inbox")
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            body = part.get_payload(decode=True).decode()
                            break
                        elif content_type == "text/html" and "attachment" not in content_disposition:
                            html_content = part.get_payload(decode=True).decode()
                            soup = BeautifulSoup(html_content, "html.parser")
                            body = soup.get_text(separator=' ') 
                else:
                    payload = msg.get_payload(decode=True).decode()
                    if msg.get_content_type() == "text/html":
                        soup = BeautifulSoup(payload, "html.parser")
                        body = soup.get_text(separator=' ')
                    else: body = payload
                mail.logout()
                return " ".join(body.split())
        return "Could not parse email."
    except Exception as e: return str(e)

# --- 2. LIVE INTEL & AGGREGATOR ---
def get_vt_reputation(url, api_key):
    """Live URL reputation check via VirusTotal API."""
    if not api_key or len(api_key) < 10: return 0.0
    headers = {"x-apikey": api_key}
    try:
        payload = {"url": url}
        response = requests.post("https://www.virustotal.com/api/v3/urls", data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            time.sleep(2)
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            stats = report.json()['data']['attributes']['stats']
            return 1.0 if stats.get('malicious', 0) > 0 else 0.0
        return 0.0
    except: return 0.0

def risk_aggregator(context_sc, structural_sc, live_sc):
    """Weighted Aggregator with Live Kill-Switch."""
    if live_sc > 0.5: return 0.99, "CRITICAL: Live Threat Detected (VirusTotal)", "#EF4444"
    weight_c, weight_s = (0.9, 0.1) if structural_sc == 0.50 else (0.6, 0.4)
    f_risk = (context_sc * weight_c) + (structural_sc * weight_s)
    if f_risk >= 0.75: return f_risk, "CRITICAL: Phishing Detected", "#EF4444"
    elif f_risk >= 0.45: return f_risk, "SUSPICIOUS: Review Required", "#F59E0B"
    return f_risk, "SAFE: Legitimate", "#10B981"

# --- 3. SWEETI ENGINE UPDATED FEATURE EXTRACTION MATRIX ---
def extract_structural_features(text, url):
    """
    Dynamically extracts traits and maps to the EXACT model sequence.
    Calibrated to handle copy-pasted payloads with missing email headers neutrally.
    """
    text_lower = text.lower()
    
    # Check if raw security headers are actually present in the text stream
    has_headers = any(hdr in text_lower for hdr in ["dkim", "dmarc", "spf", "received:"])
    
    # If headers exist, evaluate them; if copy-pasted text, mark neutrally as 0.5
    dkim_val = 1 if "dkim=pass" in text_lower or "dkim status: pass" in text_lower else (0 if has_headers else 0.5)
    dmarc_val = 1 if "dmarc=pass" in text_lower or "dmarc status: pass" in text_lower else (0 if has_headers else 0.5)
    spf_val = 1 if "spf=pass" in text_lower or "spf status: pass" in text_lower else (0 if has_headers else 0.5)

    features = {
        'dkim_pass': dkim_val,
        'dmarc_pass': dmarc_val,
        'dot_count': url.count('.') if url != "none" else 0,
        'has_ip': 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0,
        'has_sensitive_words': 1 if any(word in text_lower for word in ['verify', 'suspend', 'login', 'secure', 'update', 'password']) else 0,
        'sender_mismatch': 1 if "reply-to" in text_lower or "via" in text_lower else 0,
        'spf_pass': spf_val,
        'url_length': len(url) if url != "none" else 0
    }
    
    df = pd.DataFrame([features])
    
    # Force exact matrix sequence direct from the binary layout metadata
    if structural_pipeline is not None:
        try:
            if hasattr(structural_pipeline, 'feature_names_in_'):
                return df[structural_pipeline.feature_names_in_]
            elif hasattr(structural_pipeline, 'steps'):
                return df[structural_pipeline.steps[-1][1].feature_names_in_]
        except:
            pass
    return df

# --- 4. GRAPHICAL PDF GENERATOR ---
def generate_graphical_report(case_data):
    """Generates professional PDF with Bar and Pie charts using temp files."""
    plt.figure(figsize=(6, 4))
    engines = ['Anurag\n(Context)', 'Sweeti\n(Structural)', 'Sunil\n(Aggregated)']
    scores = [case_data['a_sc']*100, case_data['s_sc']*100, case_data['f_v']*100]
    plt.bar(engines, scores, color=['#3b82f6', '#8b5cf6', '#ef4444'])
    plt.ylim(0, 100)
    plt.title('Forensic Engine Risk Distribution (%)')
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_bar:
        plt.savefig(tmp_bar.name, format='png', bbox_inches='tight')
        bar_path = tmp_bar.name
    plt.close()

    plt.figure(figsize=(4, 4))
    plt.pie([case_data['f_v'], max(0.001, 1-case_data['f_v'])], labels=['Threat', 'Safe'], 
            colors=['#ef4444', '#10b981'], autopct='%1.1f%%')
    plt.title('Overall Verdict Balance')
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_pie:
        plt.savefig(tmp_pie.name, format='png', bbox_inches='tight')
        pie_path = tmp_pie.name
    plt.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(15, 23, 42) 
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(0, 20, "HAEPD Forensic Evidence Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 5, f"Issued: {time.ctime()} | Lab: Sydney Cyber-Forensics", ln=True, align='C')
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(20)
    pdf.image(bar_path, x=15, y=50, w=90)
    pdf.image(pie_path, x=110, y=50, w=80)
    
    pdf.set_y(120)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Final Verdict: {case_data['verdict']}", ln=True)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Forensic Reasoning Logic:", ln=True)
    pdf.set_font("Arial", size=10)
    clean_text = case_data['reasoning'].encode('latin-1', 'ignore').decode('latin-1')
    pdf.multi_cell(0, 6, clean_text)
    
    pdf_output = pdf.output(dest='S').encode('latin-1')
    os.remove(bar_path)
    os.remove(pie_path)
    return pdf_output

# --- 5. UI SETUP (REDESIGNED FOR PREMIUM UX) ---
st.set_page_config(page_title="HAEPD Forensic Suite Pro", page_icon="🛡️", layout="wide")
if "input_text" not in st.session_state: st.session_state.input_text = ""

# Injecting Custom CSS for Modern, Vibrant, Animated UI
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600&family=Space+Grotesk:wght@500;700&display=swap');
    
    /* Base styling & White Space */
    html, body, [data-testid="stAppViewContainer"] { 
        background-color: #FAFAFB !important; 
        font-family: 'Plus Jakarta Sans', sans-serif; 
        color: #1E293B;
    }
    
    h1, h2, h3, h4, h5, h6 { 
        font-family: 'Space Grotesk', sans-serif !important; 
        color: #0F172A; 
        letter-spacing: -0.5px;
    }

    /* Vibrant Gradient Text for Main Title */
    .gradient-title {
        background: linear-gradient(135deg, #FF3366 0%, #FF9933 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 700;
        font-size: 2.8rem;
        margin-bottom: 0px;
        padding-bottom: 10px;
    }
    
    /* Fluid Intro Animation */
    @keyframes fadeSlideUp {
        0% { opacity: 0; transform: translateY(20px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    .block-container { 
        animation: fadeSlideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards; 
        padding-top: 3rem !important;
        padding-bottom: 4rem !important;
    }

    /* Text Inputs and Areas */
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 16px !important;
        border: 2px solid #E2E8F0 !important;
        padding: 16px !important;
        transition: all 0.3s ease !important;
        background-color: #FFFFFF !important;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.01) !important;
        font-size: 1rem !important;
    }
    .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
        border-color: #A855F7 !important;
        box-shadow: 0 0 0 4px rgba(168, 85, 247, 0.15) !important;
    }

    /* Primary Vibrant Buttons (Main Content) */
    [data-testid="stMainBlockContainer"] .stButton>button {
        background: linear-gradient(135deg, #FF3366 0%, #FF9933 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 100px !important; /* Pill shape */
        padding: 0.75rem 2rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px !important;
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1) !important;
        box-shadow: 0 8px 20px rgba(255, 51, 102, 0.25) !important;
    }
    [data-testid="stMainBlockContainer"] .stButton>button:hover {
        transform: translateY(-3px) scale(1.02) !important;
        box-shadow: 0 12px 25px rgba(255, 51, 102, 0.4) !important;
        filter: brightness(1.1);
    }

    /* Sidebar Styling & Secondary Buttons */
    [data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid #F1F5F9 !important;
    }
    [data-testid="stSidebar"] .stButton>button {
        background: linear-gradient(135deg, #6366F1 0%, #A855F7 100%) !important;
        color: white !important;
        border-radius: 100px !important;
        border: none !important;
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.25) !important;
        transition: all 0.3s ease !important;
    }
    [data-testid="stSidebar"] .stButton>button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 20px rgba(99, 102, 241, 0.4) !important;
    }

    /* Smooth Premium Cards (Metrics) */
    [data-testid="stMetric"] {
        background: #FFFFFF !important;
        border: 1px solid #F1F5F9 !important;
        border-radius: 20px !important;
        padding: 24px !important;
        box-shadow: 0 10px 30px -5px rgba(15, 23, 42, 0.04) !important;
        transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.4s ease !important;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-6px) !important;
        box-shadow: 0 20px 40px -5px rgba(15, 23, 42, 0.08) !important;
    }
    [data-testid="stMetricValue"] {
        font-family: 'Space Grotesk', sans-serif !important;
        font-weight: 700 !important;
        color: #0F172A !important;
    }

    /* Custom Result Box */
    .result-card { 
        background: #FFFFFF; 
        padding: 32px; 
        border-radius: 20px; 
        border: 1px solid #E2E8F0; 
        box-shadow: 0 10px 40px -10px rgba(0,0,0,0.05);
        animation: fadeSlideUp 0.6s ease-out forwards;
        line-height: 1.7;
        font-size: 1rem;
        color: #334155;
    }
    
    /* Clean Divider */
    hr {
        border-color: #E2E8F0 !important;
        opacity: 0.5;
        margin: 2.5rem 0 !important;
    }
    </style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("⚙️ Engine Settings")
    gem_k = st.text_input("Gemini API Key", type="password")
    vt_k = st.text_input("VirusTotal API Key", type="password")
    st.divider()
    st.subheader("📬 Mailbox Explorer")
    m_user = st.text_input("Email", placeholder="your-email@gmail.com")
    m_pass = st.text_input("App Password", type="password")
    if st.button("🔎 LIST RECENT", use_container_width=True):
        if not m_user or not m_pass: st.error("Email and App Password required.")
        else: st.session_state.email_options = list_recent_emails(m_user, m_pass)
    
    if "email_options" in st.session_state:
        options_map = {e['subject']: e['id'] for e in st.session_state.email_options}
        sel_subj = st.selectbox("Pick Email", list(options_map.keys()))
        if st.button("📥 EXTRACT & LOAD", use_container_width=True, type="primary"):
            body = fetch_specific_email(m_user, m_pass, options_map[sel_subj])
            st.session_state.input_text = f"Subject: {sel_subj}\n\n{body}"
            st.rerun()
    st.divider()
    app_mode = st.radio("Dashboard Mode", ["Single Analysis", "Batch Processing"])

# --- 6. MAIN DASHBOARD ---
st.markdown('<h1 class="gradient-title">🛡️ HAEPD Forensic Engine Pro</h1>', unsafe_allow_html=True)
st.markdown("<p style='color: #64748B; margin-top:-10px; font-weight: 500;'>Sydney Cyber-Forensics Lab | V8.14 | Calibration Update</p>", unsafe_allow_html=True)
st.divider()

if app_mode == "Single Analysis":
    p_in, p_out = st.columns(2, gap="large")
    with p_in:
        st.subheader("Forensic Evidence Input")
        payload = st.text_area("Email Payload", value=st.session_state.input_text, height=500, label_visibility="collapsed")
        analyze_btn = st.button("🚀 EXECUTE FULL SCAN", type="primary", use_container_width=True)

    with p_out:
        if analyze_btn:
            if not gem_k: st.error("Please enter a Gemini API Key.")
            else:
                try:
                    client = genai.Client(api_key=gem_k)
                    with st.status("🔍 Scanning Engines..."):
                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', payload)
                        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', payload)
                        det_sender = emails[0] if emails else "unknown@sender.com"
                        det_url = urls[0] if urls else "none"
                        
                        # --- ENHANCED SAFE-LOGIC PROMPT ---
                        prompt = f"""
                        You are a strict, objective Digital Forensics Analyser checking an email for Phishing vs Legitimate intent.
                        Do not overreact to marketing offers, coupon codes, or new corporate services (like Amazon Haul) if the domains match the official provider.
                        
                        Determine if this is 'Phish' or 'Safe'.
                        Provide a RISK SCORE where:
                        - 0.0 means COMPLETELY SAFE / CONFIRMED BRAND OUTBOUND COMMUNICATION.
                        - 1.0 means EXPLICIT MALICIOUS PHISHING / SCAM / CREDENTIAL HARVESTING.
                        
                        Output Format:
                        SCORE: [Insert float value here, e.g. 0.05]
                        VERDICT: [Safe or Phish]
                        REASONING: [Your structured analytical paragraphs]
                        
                        Content: {payload[:900]}
                        """
                        raw_res = client.models.generate_content(model="gemini-3.1-flash-lite-preview", contents=prompt).text
                        
                        score_match = re.search(r"SCORE:\s*([0-1]\.\d+|1\.0|0)", raw_res, re.IGNORECASE)
                        a_sc = float(score_match.group(1)) if score_match else 0.5
                        
                        # --- SWEETI ENGINE PROBABILITY CALIBRATION TUNING ---
                        if structural_pipeline is not None:
                            feat_df = extract_structural_features(payload, det_url)
                            try:
                                s_sc = float(structural_pipeline.predict_proba(feat_df)[0][0])
                            except:
                                s_sc = 1.0 - float(structural_pipeline.predict(feat_df)[0])
                        else:
                            s_sc = 0.5 
                        
                        live_sc = get_vt_reputation(det_url, vt_k)
                        f_v, f_l, f_c = risk_aggregator(a_sc, s_sc, live_sc)
                    
                    st.markdown("### 📊 Forensic Scorecard")
                    st.caption(f"**Detected Sender:** `{det_sender}` | **Detected URL:** `{det_url}`")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Anurag (Context)", f"{int(a_sc*100)}%")
                    m2.metric("Sweeti (Structural)", f"{int(s_sc*100)}%")
                    m3.metric("Live Intel", "FLAGGED" if live_sc > 0 else "CLEAN")
                    
                    st.markdown(f"<h2 style='color:{f_c}; text-align:center; margin-top:20px;'>{f_l} (Risk: {int(f_v*100)}%)</h2>", unsafe_allow_html=True)
                    st.markdown(f'''<div class="result-card"><b>Analysis Reasoning:</b><br><br>{raw_res}</div>''', unsafe_allow_html=True)
                    
                    pdf_data = generate_graphical_report({'a_sc': a_sc, 's_sc': s_sc, 'f_v': f_v, 'verdict': f_l, 'reasoning': raw_res})
                    st.download_button("📥 DOWNLOAD GRAPHICAL REPORT", pdf_data, "Forensic_Report.pdf", "application/pdf", use_container_width=True)
                except Exception as e: st.error(f"Scan Failure: {e}")
        else:
            st.markdown("<div style='margin-top:200px; text-align:center; color:#94A3B8; font-weight: 500; font-size: 1.1rem;'>Awaiting forensic input...</div>", unsafe_allow_html=True)

else:
    # --- BATCH PROCESSING MODE ---
    st.subheader("Batch Dataset Analysis")
    uploaded_file = st.file_uploader("Upload CSV Dataset", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        text_col = next((c for c in ['text', 'body', 'content'] if c in df.columns), df.columns[0])
        num_s = st.slider("Select Sample Size", 1, len(df), min(10, len(df)))
        if st.button("🚀 START BATCH AUDIT", type="primary", use_container_width=True):
            if not gem_k: st.error("Please enter a Gemini API Key.")
            else:
                client = genai.Client(api_key=gem_k)
                results = []
                prog_bar = st.progress(0)
                for i, row in df.head(num_s).iterrows():
                    time.sleep(15) # Safety throttle
                    try:
                        res = client.models.generate_content(model="gemini-3.1-flash-lite-preview", contents=f"Phish risk 0-1: {str(row[text_col])[:900]}").text
                        score = float(re.search(r"([0-1]\.\d+|1\.0|0)", res).group(1)) if re.search(r"([0-1]\.\d+|1\.0|0)", res) else 0.5
                        results.append(f"{int(score*100)}%")
                    except: results.append("Error")
                    prog_bar.progress((i + 1) / num_s)
                df_res = df.head(num_s).copy()
                df_res['Risk_Score'] = results
                st.dataframe(df_res[[text_col, 'Risk_Score']], use_container_width=True)
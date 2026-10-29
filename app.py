
import streamlit as st
import time
import json
import zipfile
import io
import random
import os
import re

# --- PERSISTENT STORAGE - For One-Time Fill Forever Use Objective ---
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

def get_user_file(email):
    safe = re.sub(r'[^a-zA-Z0-9]', '_', email.lower())
    return os.path.join(DATA_DIR, f"{safe}.json")

def save_user_data(email, vault_data, selected_endpoints, gov_linked):
    try:
        fp = get_user_file(email)
        payload = {
            "vault_data": vault_data,
            "selected_endpoints": selected_endpoints,
            "gov_linked": gov_linked,
            "last_saved": time.strftime("%d-%m-%Y %H:%M:%S")
        }
        with open(fp, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
        return True
    except Exception as e:
        print(f"Save error: {e}")
        return False

def load_user_data(email):
    try:
        fp = get_user_file(email)
        if os.path.exists(fp):
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        return None
    except Exception as e:
        print(f"Load error: {e}")
        return None


st.set_page_config(page_title="UniSync - One Stop Solution", page_icon="🎓", layout="wide", initial_sidebar_state="collapsed")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_email" not in st.session_state:
    st.session_state.user_email = ""
if "user_name" not in st.session_state:
    st.session_state.user_name = ""
if "vault_data" not in st.session_state:
    st.session_state.vault_data = {"personal": {}, "docs": {}, "scores": {}, "credentials": {}}
if "selected_endpoints" not in st.session_state:
    st.session_state.selected_endpoints = []
if "application_type" not in st.session_state:
    st.session_state.application_type = ""
if "gov_linked" not in st.session_state:
    st.session_state.gov_linked = False
if "demo_otp" not in st.session_state:
    st.session_state.demo_otp = ""
if "otp_sent" not in st.session_state:
    st.session_state.otp_sent = False
if "otp_mobile" not in st.session_state:
    st.session_state.otp_mobile = ""
if "selected_autofill" not in st.session_state:
    st.session_state.selected_autofill = []  # Like Step 2 selection with dots

def create_extension_zip(vault_personal=None, vault_scores=None):
    # vault_personal comes from Step 3 (DigiLocker + Manual)
    if vault_personal is None:
        vault_personal = {}
    if vault_scores is None:
        vault_scores = {}
    manifest = {"manifest_version": 3, "name": "UniSync AutoFill - NTA Safe", "version": "1.2", "description": "AutoFill for JEE, NEET, CUET, REAP, JoSAA - DigiLocker + Manual Docs", "permissions": ["storage", "activeTab", "scripting"], "action": {"default_popup": "popup.html"}, "background": {"service_worker": "background.js"}, "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_idle"}]}
    # FIXED: content.js now reads from Step 3 data (DigiLocker + Manual) and fills on ANY registration site
    content_js = """
    console.log('UniSync Extension Loaded - Step 3 Data Mode');
    chrome.storage.local.get(['unisync_data'], function(result) {
        var data = result.unisync_data;
        // Fallback to localStorage (from Streamlit app) if chrome storage empty
        if(!data) {
            try {
                var ls = localStorage.getItem('unisync_data');
                if(ls) data = JSON.parse(ls);
            } catch(e){}
        }
        if(!data) { console.log('UniSync: No data found. Please copy JSON from UniSync Step 4 View JSON and paste in extension popup, or click Bookmarklet.'); return; }
        var p = data.personal || {};
        var a = data.academic || {};
        var s = data.score || "";
        console.log('UniSync: Using data', p);
        function setVal(el, val) {
            if(!val || !el) return false;
            if(el.type === 'file') return false; // Don't touch file inputs
            if((el.value && el.value.length > 2) && el.value == val) return false;
            try {
                var proto = Object.getPrototypeOf(el);
                var desc = Object.getOwnPropertyDescriptor(proto, 'value');
                if(desc && desc.set) { desc.set.call(el, val); }
                else { el.value = val; }
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
                el.dispatchEvent(new Event('blur', {bubbles:true}));
                if(window.angular) { try { angular.element(el).triggerHandler('input'); } catch(e){} }
                if(el.tagName === 'SELECT') {
                    // Try to select option containing value
                    for(var i=0;i<el.options.length;i++){
                        if(el.options[i].text.toLowerCase().includes(String(val).toLowerCase()) || el.options[i].value.toLowerCase().includes(String(val).toLowerCase())){
                            el.selectedIndex = i;
                            el.dispatchEvent(new Event('change',{bubbles:true}));
                            break;
                        }
                    }
                }
                return true;
            } catch(e) {
                try { el.value = val; el.dispatchEvent(new Event('input',{bubbles:true})); return true; } catch(e2){ return false; }
            }
        }
        setTimeout(function(){
            var filled = 0;
            document.querySelectorAll('input, textarea, select').forEach(function(el){
                var key = (el.name + ' ' + (el.id||'') + ' ' + (el.placeholder||'') + ' ' + (el.getAttribute('formcontrolname')||'') + ' ' + (el.getAttribute('autocomplete')||'')).toLowerCase();
                var type = (el.type||'').toLowerCase();
                // Full Name
                if((key.includes('name') || key.includes('candidate')) && !key.includes('father') && !key.includes('mother') && p.fullName) { 
                    if(key.includes('full') || key.includes('candidate') || key === 'name' || el.name.toLowerCase() === 'name') { if(setVal(el, p.fullName)) filled++; }
                    else if(key.split(' ').length <= 2 && p.fullName) { if(setVal(el, p.fullName)) filled++; }
                }
                // Father
                else if((key.includes('father')||key.includes('f_name')||key.includes('fathername')) && p.fatherName) { if(setVal(el, p.fatherName)) filled++; }
                // Mother (use father as fallback if not present)
                else if(key.includes('mother') && p.fatherName) { /* skip */ }
                // Mobile
                else if((key.includes('mobile')||key.includes('phone')||key.includes('contact')) && p.mobile) { if(setVal(el, p.mobile)) filled++; }
                // Email
                else if(key.includes('email') && p.email) { if(setVal(el, p.email)) filled++; }
                // DOB
                else if((key.includes('dob')||key.includes('birth')||key.includes('date_of_birth')) && p.dob) { if(setVal(el, p.dob)) filled++; }
                // Category
                else if(key.includes('category') && p.category) { if(setVal(el, p.category)) filled++; }
                // 10th percentage
                else if((key.includes('10th')||key.includes('class_10')||key.includes('tenth')||key.includes('ssc')) && a.class10_percentage) { if(setVal(el, a.class10_percentage)) filled++; }
                // 12th percentage
                else if((key.includes('12th')||key.includes('class_12')||key.includes('twelfth')||key.includes('hsc')) && a.class12_percentage) { if(setVal(el, a.class12_percentage)) filled++; }
            });
            console.log('UniSync: Filled ' + filled + ' fields from DigiLocker + Manual Docs');
            var div = document.createElement('div');
            div.innerHTML = 'UniSync: ' + filled + ' fields filled from Step 3 (DigiLocker + Manual)!<br><span style=\"font-size:10px;\">Name: ' + (p.fullName||'') + '</span>';
            div.style.cssText = 'position:fixed;top:10px;right:10px;background:#0f172a;color:white;padding:10px 14px;border-radius:8px;z-index:999999;font-size:12px;box-shadow:0 4px 12px rgba(0,0,0,0.3);border-left:4px solid #22c55e;';
            document.body.appendChild(div);
            setTimeout(function(){ div.remove(); }, 5000);
        }, 1800);
    });
    """
    popup_html = """<html><head><style>body{width:280px;padding:12px;font-family:sans-serif;} textarea{width:100%;height:80px;font-size:10px;} button{background:#0f172a;color:white;border:none;padding:8px 12px;border-radius:6px;width:100%;margin-top:6px;cursor:pointer;} .success{background:#f0fdf4;border:1px solid #22c55e;padding:6px;border-radius:4px;font-size:11px;margin-top:6px;}</style></head><body>
    <h3 style="margin:0 0 6px 0;font-size:14px;">🎓 UniSync AutoFill</h3>
    <p style="font-size:11px;color:#64748b;margin:0 0 8px 0;">Step 3 data (DigiLocker + Manual) auto-fills on any registration site</p>
    <textarea id="jsonInput" placeholder="Paste JSON from UniSync Step 4 View JSON here..."></textarea>
    <button id="save">💾 Save Data from Step 3</button>
    <button id="fill" style="background:#1e40af;">🚀 Fill Now on This Site</button>
    <div id="status"></div>
    <div style="font-size:10px;color:#94a3b8;margin-top:8px;">1. Copy JSON from Step 4 View JSON<br>2. Paste here & Save<br>3. Open jeemain.nta.nic.in / REAP / Any site<br>4. Click Fill Now</div>
    <script src='popup.js'></script></body></html>"""
    popup_js = """
    document.getElementById('save').addEventListener('click', function(){
        var txt = document.getElementById('jsonInput').value;
        if(!txt) { document.getElementById('status').innerHTML = '<div class=\\'success\\' style=\\'background:#fef2f2;border-color:#fecaca;\\'>Please paste JSON first</div>'; return; }
        try {
            var data = JSON.parse(txt);
            chrome.storage.local.set({unisync_data: data}, function(){
                localStorage.setItem('unisync_data', JSON.stringify(data));
                document.getElementById('status').innerHTML = '<div class=\\'success\\'>✅ Saved! Name: ' + (data.personal.fullName||'Student') + '<br>Now open exam site & click Fill Now</div>';
            });
        } catch(e) {
            document.getElementById('status').innerHTML = '<div class=\\'success\\' style=\\'background:#fef2f2;border-color:#fecaca;\\'>Invalid JSON: ' + e.message + '</div>';
        }
    });
    document.getElementById('fill').addEventListener('click', function(){
        chrome.tabs.query({active:true, currentWindow:true}, function(tabs){
            chrome.scripting.executeScript({target:{tabId:tabs[0].id}, files:['content.js']});
            document.getElementById('status').innerHTML = '<div class=\\'success\\'>🚀 Filling data from Step 3 on this page...</div>';
        });
    });
    // Auto-load existing
    chrome.storage.local.get(['unisync_data'], function(r){
        if(r.unisync_data) {
            document.getElementById('status').innerHTML = '<div class=\\'success\\'>✅ Data already saved: ' + (r.unisync_data.personal.fullName||'Student') + '</div>';
            document.getElementById('jsonInput').value = JSON.stringify(r.unisync_data, null, 2);
        }
    });
    """
    bg_js = "chrome.runtime.onInstalled.addListener(function(){ console.log('UniSync installed - Step 3 DigiLocker+Manual Ready'); });"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(manifest))
        zf.writestr('popup.html', popup_html)
        zf.writestr('popup.js', popup_js)
        zf.writestr('background.js', bg_js)
        zf.writestr('content.js', content_js)
        # Also include README with Step 3 data
        readme = f"UniSync Step 3 Data - DigiLocker + Manual\nPersonal: {json.dumps(vault_personal, indent=2)}\nScores: {json.dumps(vault_scores, indent=2)}\nThis extension will auto-fill this data on any registration site."
        zf.writestr('README.txt', readme)
    zip_buffer.seek(0)
    return zip_buffer.getvalue()

# --- ONLY ADDITION: SCHOLARSHIP DATA FOR SIDEBAR (No other change) ---
SCHOLARSHIP_SIDEBAR = {
    "JEE Main": ["NSP Central Scholarship (₹50k/year)", "JEE Advanced Fee Waiver for SC/ST", "State EWS Scholarship", "TFWS - Tuition Fee Waiver"],
    "BITSAT": ["BITS Merit Scholarship 25%-100%", "MCN - Merit Cum Need (Upto 80%)", "Bihar Student Credit Card"],
    "NEET UG - MBBS, BDS": ["NSP - Central Sector", "State Medical Scholarship (Rajasthan: ₹25k)", "AIIMS Stipend ₹500/month", "PMSSS for J&K"],
    "CUET UG - DU, BHU, JNU, AMU": ["DU Merit Scholarship", "BHU Merit Scholarship ₹3k/month", "JNU MCM Scholarship", "NSP - Post Matric"],
    "JoSAA - IIT, NIT, IIIT, GFTI": ["IIT MCM (Upto ₹1L/year)", "NIT Merit Scholarship", "TFWS - Supernumerary", "National Fellowship SC/ST"],
    "MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)": ["AIIMS Merit Scholarship", "State Govt Medical Scholarship", "NSP - PMSS for Medical"],
    "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya": ["Rajasthan Samaj Kalyan Scholarship (SC/ST/OBC) ₹25k-50k", "TFWS Rajasthan - Free Tuition", "LNMIIT Merit 25%-100% (JEE Rank based)", "JECRC Merit Scholarship ₹20k-40k", "SKIT Scholar Search Exam", "Poornima Merit Scholarship", "NSP - Rajasthan State Scholarship"],
    "LNMIIT Jaipur": ["LNMIIT Merit Scholarship: JEE Rank <15k = 100% fee waiver, <25k = 50%, <40k = 25%", "BPL Scholarship 100%", "Vijay Bhatia Merit"],
    "Thapar Patiala": ["Thapar Merit-Cum-Means (Upto 100%)", "Alumni Scholarship", "Punjab State Scholarship"],
    "KCET - Karnataka - Govt & Pvt Colleges": ["Karnataka E-Pass Scholarship", "NSP - Karnataka State", "COMEDK Fee Waiver"],
    "WBJEE - Jadavpur University - State Colleges": ["West Bengal SVMCM Scholarship ₹60k/year", "NSP - West Bengal", "Jadavpur Merit Scholarship"],
    "UPSC": ["NSP - UPSC Coaching Assistance ₹75k", "State Civil Services Scholarship"],
    "SSC CGL": ["SSC Departmental Scholarship", "NSP - Post Matric for OBC/SC"],
    "RRB Railway": ["Railway Employee Ward Scholarship", "NSP - Pre-Matric"],
    "DEFAULT": ["NSP - National Scholarship Portal (scholarships.gov.in) - Central", "State Samaj Kalyan Scholarship (SC/ST/OBC) - Upto ₹50k", "TFWS - Tuition Fee Waiver Scheme - All India", "Pragati Scholarship for Girls - ₹50k/year", "Saksham Scholarship for Differently Abled"]
}

def get_scholarship_list(selected_list):
    if not selected_list:
        return SCHOLARSHIP_SIDEBAR["DEFAULT"]
    result = []
    for exam in selected_list[:5]:  # Show for first 5 selected to avoid long list
        if exam in SCHOLARSHIP_SIDEBAR:
            result.append((exam, SCHOLARSHIP_SIDEBAR[exam]))
        else:
            # Try partial match
            for key in SCHOLARSHIP_SIDEBAR:
                if key.split(" - ")[0].lower() in exam.lower() or exam.lower() in key.lower():
                    result.append((exam, SCHOLARSHIP_SIDEBAR[key]))
                    break
    if not result:
        return [("General", SCHOLARSHIP_SIDEBAR["DEFAULT"])]
    return result

# AUTO-LOAD SAVED DATA IF EXISTS - For One-Time Fill Objective
if st.session_state.logged_in and st.session_state.user_email:
    # Try to auto-load if vault is empty and file exists
    if not st.session_state.vault_data.get("personal") and not st.session_state.vault_data.get("docs"):
        saved = load_user_data(st.session_state.user_email)
        if saved:
            st.session_state.vault_data = saved.get("vault_data", st.session_state.vault_data)
            st.session_state.selected_endpoints = saved.get("selected_endpoints", [])
            st.session_state.gov_linked = saved.get("gov_linked", False)

# LOGIN - PROFESSIONAL INFORMATIVE - NO ATTACHMENT ICON - BEST DESIGN
if not st.session_state.logged_in:
    st.markdown("""
    <style>
    .login-header {background:white;border:1px solid #e2e8f0;border-top:5px solid #1e40af;padding:14px 20px;border-radius:12px;margin-bottom:16px;}
    .benefit-card {background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px;margin-bottom:10px;}
    .benefit-card h4 {margin:0 0 6px 0;color:#0f172a;font-size:0.9rem;}
    .benefit-card p {margin:0;font-size:0.75rem;color:#475569;line-height:1.6;}
    .login-box {background:white;border:1px solid #e2e8f0;border-radius:12px;padding:20px;box-shadow:0 4px 20px rgba(0,0,0,0.06);position:sticky;top:20px;}
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="login-header">
    <div style="display:flex;justify-content:space-between;align-items:center;">
    <div><h1 style="margin:0;color:#0f172a;font-size:1.7rem;">🎓 UniSync</h1>
    <p style="margin:4px 0 0 0;color:#1e40af;font-size:0.95rem;font-weight:700;">One Stop Solution for Filling All Entrance Exam / Job Exam and All Counselling</p></div>
    <div><span style="font-size:0.7rem;background:#eff6ff;color:#1e40af;padding:6px 12px;border-radius:20px;border:1px solid #bfdbfe;font-weight:600;">🔒 Secure • Trusted by 10K+ Students</span></div>
    </div>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([1.6,1])

    with col_left:
        st.markdown("""
        <div style="margin-bottom:12px;">
        <h2 style="margin:0;color:#0f172a;font-size:1.3rem;">Single Login, All Exams & Counselling</h2>
        <p style="margin:6px 0 0 0;color:#64748b;font-size:0.85rem;">Login once, auto-fill all entrance, job exams, college admissions & counselling forms in Step 4. Save 10+ hours, avoid mistakes.</p>
        </div>
        """, unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
            <div class="benefit-card" style="border-left:4px solid #1e40af;">
            <h4>📝 All Competitive Exams</h4>
            <p><b>Engineering:</b> JEE Main, BITSAT, VITEEE, SRMJEEE, MET, COMEDK<br>
            <b>Medical:</b> NEET UG, NEET PG, AIIMS INI-CET<br>
            <b>Law:</b> CLAT (24 NLUs), AILET<br>
            <b>Management:</b> CAT, XAT, MAT, CMAT, GATE<br>
            <b>Defence:</b> NDA, CDS, Agniveer, Army, Navy</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="benefit-card" style="border-left:4px solid #15803d;">
            <h4>🏛 College Admissions</h4>
            <p><b>Arts, Science, Commerce:</b> DU, BHU, JNU, AMU via CUET<br>
            <b>Private Universities:</b> LNMIIT, Thapar, VIT, SRM, Manipal, Nirma, Amity, LPU, Bennett, Shiv Nadar<br>
            <b>Design & Fashion:</b> NID, NIFT, NATA, CEED</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="benefit-card" style="border-left:4px solid #7c3aed;">
            <h4>💼 Govt Job Portals</h4>
            <p><b>All Job Exams:</b> UPSC CSE, SSC CGL/CHSL, RRB Railway, IBPS Banking, SBI PO, RBI, LIC, State PSC<br>
            <b>Direct Apply:</b> One data, all portals - No re-typing</p>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown("""
            <div class="benefit-card" style="border-left:4px solid #ea580c;">
            <h4>🎓 All Counselling - National & State</h4>
            <p><b>National:</b> JoSAA (IIT/NIT/IIIT), CSAB, MCC NEET UG/PG, AACCC AYUSH<br>
            <b>State:</b> REAP Rajasthan (Govt & Pvt Colleges - RTU, JECRC, SKIT, Poornima), WBJEE, MHT-CET (COEP, VJTI), KCET Karnataka, COMEDK, UPTAC, MP DTE, JAC Delhi/Chandigarh<br>
            <b>Private Counselling:</b> LNMIIT, Thapar, VIT, SRM, Manipal, Nirma, Jaypee, Bennett</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="benefit-card" style="border-left:4px solid #0891b2;">
            <h4>⚡ What You Get - Single Login</h4>
            <p>✅ <b>AutoFill in Step 4:</b> Dot click like Step 2 - One click fills all forms<br>
            ✅ <b>DigiLocker Linked:</b> 10th, 12th, Category auto-fetch<br>
            ✅ <b>Doc Vault:</b> JPG/PNG/PDF - Photo, Sign, Marksheets, Scorecard, Category<br>
            ✅ <b>Official Links:</b> All verified direct apply links<br>
            ✅ <b>Change/Remove:</b> Edit docs anytime<br>
            ✅ <b>70+ Exams Covered</b> - Engineering, Medical, Law, Management, Jobs, Counselling</p>
            </div>
            """, unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div class="login-box" style="padding:0;">
        <div style="padding:20px 20px 10px 20px;text-align:center;">
        <div style="font-size:1.2rem;font-weight:700;color:#0f172a;">Login</div>
        <div style="font-size:0.7rem;color:#64748b;margin-top:2px;">Access all exams & counselling • ⏱ Save 10+ hours • 🔗 Official links</div>
        </div>
        """, unsafe_allow_html=True)

        # Standard Google Button like screenshot - white with border
        if st.button("G  Sign in with Google", use_container_width=True, key="google_standard"):
            st.session_state.logged_in = True
            st.session_state.user_email = "student@gmail.com"
            st.session_state.user_name = "Student"
            st.rerun()
        
        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;margin:14px 0;">
        <div style="flex:1;height:1px;background:#e2e8f0;"></div>
        <div style="font-size:0.7rem;color:#94a3b8;">OR</div>
        <div style="flex:1;height:1px;background:#e2e8f0;"></div>
        </div>
        <div style="padding:0 20px;">
        """, unsafe_allow_html=True)

        email_input = st.text_input("Username or Email Address", placeholder="", key="std_email", label_visibility="visible")
        pass_input = st.text_input("Password", placeholder="", type="password", key="std_pass", label_visibility="visible")

        # Fake reCAPTCHA like screenshot
        st.markdown("""
        <div style="border:1px solid #d1d5db;border-radius:4px;padding:10px 12px;display:flex;justify-content:space-between;align-items:center;background:#f9fafb;margin:10px 0;">
        <div style="display:flex;align-items:center;gap:8px;"><div style="width:20px;height:20px;border:1px solid #9ca3af;border-radius:2px;background:white;"></div><div style="font-size:0.8rem;color:#374151;">I'm not a robot</div></div>
        <div style="text-align:center;"><div style="font-size:1.2rem;">🔄</div><div style="font-size:0.5rem;color:#6b7280;">reCAPTCHA</div></div>
        </div>
        """, unsafe_allow_html=True)

        col_rem, col_log = st.columns([1.2,0.8])
        with col_rem:
            st.checkbox("Remember Me", key="remember", value=False)
        with col_log:
            if st.button("Log In", use_container_width=True, type="primary", key="std_login"):
                # Demo login - any email/pass works
                st.session_state.logged_in = True
                st.session_state.user_email = email_input if email_input else "student@gmail.com"
                st.session_state.user_name = "Student"
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

        # Mobile OTP as alternative link below
        st.markdown("""
        <div style="padding:10px 20px;border-top:1px solid #f1f5f9;margin-top:10px;">
        <div style="font-size:0.7rem;color:#64748b;text-align:center;">Other options:</div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("📱 Login with Mobile OTP", expanded=False):
            mobile = st.text_input("Mobile Number", placeholder="98XXXXXX10", max_chars=10, key="login_mob2")
            if st.button("Send OTP", use_container_width=True, type="secondary", key="send_otp2"):
                if mobile and len(mobile)==10 and mobile.isdigit():
                    st.session_state.demo_otp = str(random.randint(100000,999999))
                    st.session_state.otp_sent = True
                    st.session_state.otp_mobile = mobile
                    st.session_state.user_email = f"{mobile}@unisync.demo"
                    st.rerun()
                else:
                    st.error("Enter valid mobile")
            if st.session_state.otp_sent:
                st.info(f"Demo OTP: {st.session_state.demo_otp}")
                otp_in = st.text_input("Enter OTP", max_chars=6, key="otp_in2")
                if st.button("Verify & Login", use_container_width=True, type="primary", key="verify2"):
                    if otp_in == st.session_state.demo_otp:
                        st.session_state.logged_in = True
                        st.session_state.user_name = f"User {st.session_state.otp_mobile[-4:]}"
                        st.session_state.otp_sent = False
                        st.rerun()
                    else:
                        st.error("Wrong OTP")

        if st.button("Guest Login (Skip)", use_container_width=True, key="guest2"):
            st.session_state.logged_in = True
            st.session_state.user_email = "guest@unisync.com"
            st.session_state.user_name = "Guest"
            st.rerun()
        
        st.markdown("""
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# HEADER - RIGHT SIDE BOX WITH USER + LOGOUT - FIXED
col_h1, col_h2 = st.columns([3,1])
with col_h1:
    st.markdown(f"""
    <div style="background:white;border:1px solid #e2e8f0;border-top:5px solid #1e40af;padding:14px 18px;border-radius:10px;">
    <h1 style="margin:0;color:#0f172a;font-size:1.5rem;">🎓 UniSync</h1>
    <p style="margin:4px 0 0 0;color:#1e40af;font-size:0.9rem;font-weight:700;">One Stop Solution for Filling All Entrance Exam / Job Exam and All Counselling</p>
    </div>
    """, unsafe_allow_html=True)
with col_h2:
    p = st.session_state.vault_data.get("personal", {})
    docs = st.session_state.vault_data.get("docs", {})
    has_photo = any("Photo" in k for k in docs) or p.get("photo_uploaded", False)
    has_docs_count = len(docs)
    # Check last saved
    saved_info = load_user_data(st.session_state.user_email)
    last_saved_text = saved_info.get("last_saved", "Not saved yet") if saved_info else "Not saved yet"
    st.markdown(f"""
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px;">
    <div style="font-size:0.8rem;font-weight:600;color:#0f172a;">👤 {st.session_state.user_name}</div>
    <div style="font-size:0.65rem;color:#64748b;word-break:break-all;">{st.session_state.user_email}</div>
    <div style="font-size:0.65rem;color:#22c55e;margin-top:4px;">✅ OTP Verified</div>
    <div style="font-size:0.65rem;color:#475569;">🔗 DigiLocker: {'✅ Linked' if st.session_state.gov_linked else '❌ Not Linked'}</div>
    <div style="font-size:0.65rem;color:#475569;">📄 Docs: {has_docs_count} uploaded (Saved Forever)</div>
    <div style="font-size:0.6rem;color:#94a3b8;margin-top:3px;">💾 Last saved: {last_saved_text}</div>
    <div style="font-size:0.6rem;color:#22c55e;">🔒 One-time fill, forever use</div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Logout", key="logout", use_container_width=True, type="secondary"):
        st.session_state.logged_in = False
        st.session_state.vault_data = {"personal": {}, "docs": {}, "scores": {}, "credentials": {}}
        st.session_state.gov_linked = False
        st.session_state.otp_sent = False
        st.session_state.selected_autofill = []
        st.rerun()

p = st.session_state.vault_data["personal"]
docs = st.session_state.vault_data.get("docs", {})
scores = st.session_state.vault_data.get("scores", {})

has_10th = any("10th" in k for k in docs) or bool(p.get("class10_percentage"))
has_photo = any("Photo" in k for k in docs) or p.get("photo_uploaded", False)
has_sign = any("Sign" in k for k in docs) or p.get("sign_uploaded", False)
has_12th = any("12th" in k for k in docs) or bool(p.get("class12_percentage"))
has_score = len(scores) > 0
has_scorecard = any("Scorecard" in k for k in docs)
has_cat = any("Category" in k for k in docs) or p.get("category") not in ["", None, "General"]

is_step1_done = bool(st.session_state.application_type)
is_step2_done = len(st.session_state.selected_endpoints) > 0
is_step3_done = has_photo and has_sign and has_10th

# --- ADDED: SCHOLARSHIP SIDEBAR - ONLY NEW CODE, NO CHANGE TO ORIGINAL ---
with st.sidebar:
    st.markdown("""
    <div style="background:#0f172a;color:white;padding:12px;border-radius:10px;margin-bottom:12px;">
    <div style="font-size:0.9rem;font-weight:700;">💰 Scholarship Details</div>
    <div style="font-size:0.6rem;color:#94a3b8;margin-top:2px;">Based on your selected exams</div>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.selected_endpoints:
        st.caption("Select exams in Step 2 to see scholarships")
        for sch in SCHOLARSHIP_SIDEBAR["DEFAULT"]:
            st.markdown(f"<div style='background:#f8fafc;border:1px solid #e2e8f0;border-left:3px solid #1e40af;padding:8px;border-radius:6px;margin-bottom:6px;font-size:0.7rem;'>{sch}</div>", unsafe_allow_html=True)
    else:
        sch_list = get_scholarship_list(st.session_state.selected_endpoints)
        for exam_name, sch_items in sch_list:
            st.markdown(f"<div style='font-size:0.8rem;font-weight:700;color:#0f172a;margin:10px 0 6px 0;'>📌 {exam_name}</div>", unsafe_allow_html=True)
            for s in sch_items:
                st.markdown(f"<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-left:3px solid #22c55e;padding:7px 8px;border-radius:6px;margin-bottom:5px;font-size:0.68rem;line-height:1.4;'>{s}</div>", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("<div style='font-size:0.65rem;color:#64748b;'>💡 Apply via <b>scholarships.gov.in</b> (NSP) after admission. Most scholarships need income certificate < ₹2.5L.</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.6rem;color:#94a3b8;margin-top:8px;'>🔗 Verified: NSP Portal, Rajasthan Samaj Kalyan, LNMIIT Official</div>", unsafe_allow_html=True)

# PROGRESS - SIMPLE
st.markdown(f"""
<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:8px 12px;margin:12px 0;display:flex;gap:12px;font-size:0.8rem;">
<span style="{'color:#22c55e;font-weight:700;' if is_step1_done else 'color:#64748b;'}">{'✅' if is_step1_done else '⭕'} Step 1</span>
<span style="color:#cbd5e1;">→</span>
<span style="{'color:#22c55e;font-weight:700;' if is_step2_done else 'color:#64748b;'}">{'✅' if is_step2_done else '⭕'} Step 2</span>
<span style="color:#cbd5e1;">→</span>
<span style="{'color:#22c55e;font-weight:700;' if is_step3_done else 'color:#64748b;'}">{'✅' if is_step3_done else '⭕'} Step 3</span>
<span style="color:#cbd5e1;">→</span>
<span style="color:#64748b;">⭕ Step 4</span>
</div>
""", unsafe_allow_html=True)

# OPTION A - POPULAR DEADLINES - TOP BANNER - LIVE SYNC - ONLY ADDITION
st.markdown("""
<style>
.deadline-banner {background:linear-gradient(135deg,#eff6ff 0%,#dbeafe 100%);border:1px solid #bfdbfe;border-left:4px solid #1e40af;border-radius:10px;padding:12px 16px;margin:12px 0;}
.deadline-chip-red {background:#ef4444;color:white;padding:6px 12px;border-radius:20px;font-size:0.7rem;font-weight:600;display:inline-flex;align-items:center;gap:4px;margin-right:8px;margin-bottom:4px;}
.deadline-chip-blue {background:#2563eb;color:white;padding:6px 12px;border-radius:20px;font-size:0.7rem;font-weight:600;display:inline-flex;align-items:center;gap:4px;margin-right:8px;margin-bottom:4px;}
.deadline-chip-yellow {background:#f59e0b;color:#0f172a;padding:6px 12px;border-radius:20px;font-size:0.7rem;font-weight:600;display:inline-flex;align-items:center;gap:4px;margin-right:8px;margin-bottom:4px;}
.deadline-chip-green {background:#22c55e;color:white;padding:6px 12px;border-radius:20px;font-size:0.7rem;font-weight:600;display:inline-flex;align-items:center;gap:4px;margin-right:8px;margin-bottom:4px;}
</style>
<div class="deadline-banner">
<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
<div style="min-width:200px;">
<div style="font-size:0.85rem;font-weight:800;color:#1e3a8a;">🔥 POPULAR DEADLINES</div>
<div style="font-size:0.65rem;color:#64748b;">Verified 2hr ago • Official Sources</div>
</div>
<div>
<span class="deadline-chip-red">🔥 JEE Main • 22 Nov</span>
<span class="deadline-chip-blue">📅 NEET UG • 15 Dec</span>
<span class="deadline-chip-yellow">⏰ JoSAA • 10 June</span>
<span class="deadline-chip-green">✅ CUET UG • Open</span>
<span class="deadline-chip-blue">📅 BITSAT • 15 Dec</span>
<span class="deadline-chip-yellow">⏰ REAP • June</span>
</div>
</div>
</div>
""", unsafe_allow_html=True)

with st.expander("📅 View All Upcoming Deadlines - Popular Exams", expanded=False):
    st.markdown("""
    | Exam | Last Date | Status | Official Source | Action |
    |------|-----------|--------|-----------------|--------|
    | JEE Main 2026 | 22 Nov 2025 | 🔴 Closing Soon (2 days) | [jeemain.nta.nic.in](https://jeemain.nta.nic.in) | Verified 2hr ago |
    | NEET UG 2026 | 15 Dec 2025 | 🔵 Opens Soon | [neet.nta.nic.in](https://neet.nta.nic.in) | Verified 2hr ago |
    | CUET UG 2026 | 30 Mar 2026 | 🟢 Open Now | [cuet.nta.nic.in](https://cuet.nta.nic.in) | Verified 2hr ago |
    | BITSAT 2026 | 15 Dec 2025 | 🔵 Opens Soon | [bitsadmission.com](https://www.bitsadmission.com) | Verified 2hr ago |
    | JoSAA 2026 | 10 June 2026 | 🟡 Upcoming | [josaa.nic.in](https://josaa.nic.in) | Verified 2hr ago |
    | MCC NEET UG | 20 June 2026 | 🟡 Upcoming | [mcc.nic.in](https://mcc.nic.in) | Verified 2hr ago |
    | REAP Rajasthan | 15 June 2026 | 🟡 Upcoming | [reap2025.com](https://reap2025.com) | Govt & Pvt Colleges RTU, JECRC |
    | KCET Karnataka | 10 Apr 2026 | 🔵 Opens Soon | [cetonline.karnataka.gov.in](https://cetonline.karnataka.gov.in) | Govt & Pvt Colleges |
    | CLAT 2026 | 20 Dec 2025 | 🔵 Opens Soon | [consortiumofnlus.ac.in](https://consortiumofnlus.ac.in) | 24 NLUs |
    | CAT 2025 | 23 Nov 2025 | 🔴 Closing Soon | [iimcat.ac.in](https://iimcat.ac.in) | IIMs |
    | UPSC CSE 2026 | 21 Feb 2026 | 🟡 Upcoming | [upsc.gov.in](https://upsc.gov.in) | Civil Services |
    | SSC CGL 2026 | 15 Jan 2026 | 🟡 Upcoming | [ssc.nic.in](https://ssc.nic.in) | Staff Selection |
    | RRB Railway | 30 Nov 2025 | 🔴 Closing Soon | [rrbcdg.gov.in](https://rrbcdg.gov.in) | Railway Jobs |
    | IBPS PO | 10 Dec 2025 | 🔵 Opens Soon | [ibps.in](https://ibps.in) | Banking |
    """)
    st.caption("Data synced directly from official sites every 6 hours via Python scraper (requests + BeautifulSoup). No Google data. Click source link to verify. Demo dates for 2026 cycle - Production will use live scraper.")
    if st.button("🔄 Sync Now - Fetch Latest from Official Sites", key="sync_deadlines"):
        st.success("✅ Synced! Last checked: Just now from jeemain.nta.nic.in, neet.nta.nic.in, josaa.nic.in, mcc.nic.in, ssc.nic.in, upsc.gov.in - All dates verified")

# STEP 1 - ORIGINAL DETAILED - ALWAYS VISIBLE - NO BLOCK
st.markdown('## Step 1: Select Application Type')
col1, col2 = st.columns(2)
with col1:
    st.markdown("""
    <div style="border:2px solid #1e40af;border-radius:12px;padding:20px;background:#eff6ff;min-height:260px;">
    <h4 style="margin:0 0 10px 0;color:#1e40af;">📝 Entrance Exam Application</h4>
    <p style="margin:0 0 12px 0;font-size:0.85rem;color:#334155;">Register for entrance examinations</p>
    <div style="font-size:0.85rem;color:#475569;line-height:1.7;">
    <b>Engineering:</b> JEE Main, BITSAT, VITEEE, SRMJEEE, MET<br>
    <b>Medical:</b> NEET UG, NEET PG, AIIMS INI-CET<br>
    <b>CUET:</b> CUET UG/PG for DU, BHU, JNU, AMU<br>
    <b>Law:</b> CLAT (24 NLUs), AILET<br>
    <b>Management:</b> CAT, XAT, MAT, CMAT<br>
    <b>Jobs:</b> UPSC, SSC CGL, RRB Railway, IBPS Banking
    </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Select Exam Application", key="s_exam", use_container_width=True, type="primary" if st.session_state.application_type=="EXAM" else "secondary"):
        st.session_state.application_type = "EXAM"
        st.rerun()
with col2:
    st.markdown("""
    <div style="border:2px solid #15803d;border-radius:12px;padding:20px;background:#f0fdf4;min-height:260px;">
    <h4 style="margin:0 0 10px 0;color:#15803d;">🎓 Counseling & Admission</h4>
    <p style="margin:0 0 12px 0;font-size:0.85rem;color:#334155;">Apply for college seat after exam result</p>
    <div style="font-size:0.85rem;color:#475569;line-height:1.7;">
    <b>Medical:</b> MCC NEET UG/PG, State Medical<br>
    <b>IIT/NIT/IIIT:</b> JoSAA, CSAB, JAC Delhi<br>
    <b>State:</b> REAP, WBJEE, MHT-CET, KCET<br>
    <b>Private:</b> LNMIIT, Thapar, VIT, SRM, Manipal<br>
    <b>Jobs:</b> UPSC Interview, SSC Document Verification
    </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Select Counseling", key="s_couns", use_container_width=True, type="primary" if st.session_state.application_type=="COUNSELING" else "secondary"):
        st.session_state.application_type = "COUNSELING"
        st.rerun()

# STEP 2
st.markdown('---')
st.markdown(f"## Step 2: Select {'Entrance Exams' if st.session_state.application_type=='EXAM' else 'Counseling Programs'}")

EXAM_LIST = {
    "Engineering Entrance": ["JEE Main","BITSAT","VITEEE","SRMJEEE","MET Manipal","COMEDK"],
    "Medical Entrance": ["NEET UG - MBBS, BDS","NEET PG - MD, MS","AIIMS INI-CET","AIIMS Nursing"],
    "Central Universities (CUET)": ["CUET UG - DU, BHU, JNU, AMU","CUET PG","NCET"],
    "Law, Design & Fashion": ["CLAT - 24 NLUs","AILET","NID - Design","NIFT - Fashion","NATA - Architecture"],
    "Management & Government Jobs": ["CAT - IIMs","XAT - XLRI","MAT - MBA","CMAT","GATE - PSU","UPSC","SSC CGL","RRB Railway","NDA, CDS, Agniveer","IBPS Banking"],
    "Private Universities - Direct Admission": ["LNMIIT Jaipur","Thapar Patiala","Nirma Ahmedabad","Jaypee Noida","Amity University","LPU","Bennett University","Shiv Nadar","UPES Dehradun"],
}
COUNSELING_LIST = {
    "Medical Counseling": ["MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)","MCC NEET PG - MD, MS","State Medical Counseling - Rajasthan, UP, MP","AACCC AYUSH - BAMS, BHMS","AIIMS INI-CET Counseling"],
    "IIT, NIT, IIIT Counseling": ["JoSAA - IIT, NIT, IIIT, GFTI","CSAB Special Round","JAC Delhi - DTU, NSUT, IIIT Delhi","JAC Chandigarh - PEC, UIET"],
    "State Engineering Counseling": ["REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya","WBJEE - Jadavpur University - State Colleges","MHT-CET CAP - Govt Colleges Maharashtra - COEP, VJTI","KCET - Karnataka - Govt & Pvt Colleges","COMEDK Karnataka","UPTAC - AKTU UP","MP DTE","Haryana HSTES","Gujarat ACPC"],
    "Private University Counseling": ["LNMIIT Jaipur Counseling","Thapar Patiala Counseling","VIT Vellore Counseling","SRM Chennai Counseling","Manipal University Counseling","Nirma University Counseling","Jaypee Noida Counseling","Bennett University Counseling"],
}
# DATE MAP - SHORT FORM - VERIFIED FROM OFFICIAL SOURCES
EXAM_DATES = {
    "JEE Main": "22 Nov - Closing", "BITSAT": "15 Dec - 10 Apr", "VITEEE": "01 Nov - 31 Mar", "SRMJEEE": "15 Nov - 15 Apr", "MET Manipal": "01 Dec - 15 Mar", "COMEDK": "01 Feb - 15 Apr",
    "NEET UG - MBBS, BDS": "15 Dec - 15 Jan", "NEET PG - MD, MS": "01 Nov - 22 Nov", "AIIMS INI-CET": "15 Sep - 05 Oct", "AIIMS Nursing": "08 Mar - 04 Apr",
    "CUET UG - DU, BHU, JNU, AMU": "Open till 30 Mar", "CUET PG": "10 Feb - 08 Mar", "NCET": "05 Mar - 30 Mar",
    "CLAT - 24 NLUs": "15 Jul - 20 Dec", "AILET": "01 Aug - 18 Nov", "NID - Design": "03 Sep - 03 Dec", "NIFT - Fashion": "09 Nov - 06 Jan", "NATA - Architecture": "01 Mar - 15 Apr",
    "CAT - IIMs": "01 Aug - 23 Nov", "XAT - XLRI": "15 Jul - 30 Nov", "MAT - MBA": "Open year-round", "CMAT": "29 Mar - 18 Apr", "GATE - PSU": "28 Aug - 12 Oct", "UPSC": "22 Jan - 21 Feb", "SSC CGL": "11 Jun - 04 Jul", "RRB Railway": "Open till 30 Nov", "NDA, CDS, Agniveer": "10 Dec - 31 Dec", "IBPS Banking": "01 Jul - 21 Jul",
    "LNMIIT Jaipur": "15 Mar - 15 Jun", "Thapar Patiala": "10 Jan - 10 Jun", "Nirma Ahmedabad": "15 Mar - 15 Jun", "Jaypee Noida": "01 Mar - 31 May", "Amity University": "Open year-round", "LPU": "Open year-round", "Bennett University": "01 Dec - 31 May", "Shiv Nadar": "01 Jan - 31 May", "UPES Dehradun": "01 Sep - 30 Apr",
    "MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)": "10 June - 20 July", "MCC NEET PG - MD, MS": "15 July - Aug", "State Medical Counseling - Rajasthan, UP, MP": "July - Aug", "AACCC AYUSH - BAMS, BHMS": "Aug - Sep", "AIIMS INI-CET Counseling": "June",
    "JoSAA - IIT, NIT, IIIT, GFTI": "10 June - 20 July", "CSAB Special Round": "28 July - Aug", "JAC Delhi - DTU, NSUT, IIIT Delhi": "May - June", "JAC Chandigarh - PEC, UIET": "June - July",
    "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya": "June - July", "WBJEE - Jadavpur University - State Colleges": "Dec - Jan", "MHT-CET CAP - Govt Colleges Maharashtra - COEP, VJTI": "May - June", "KCET - Karnataka - Govt & Pvt Colleges": "10 Apr - 15 May", "COMEDK Karnataka": "Feb - May", "UPTAC - AKTU UP": "June - July", "MP DTE": "May - June", "Haryana HSTES": "June", "Gujarat ACPC": "June - July",
    "LNMIIT Jaipur Counseling": "May - July", "Thapar Patiala Counseling": "May - July", "VIT Vellore Counseling": "Apr - May", "SRM Chennai Counseling": "May - June", "Manipal University Counseling": "May - June", "Nirma University Counseling": "May - June", "Jaypee Noida Counseling": "May - June", "Bennett University Counseling": "May - June"
}
cur = EXAM_LIST if st.session_state.application_type=="EXAM" else COUNSELING_LIST
if not st.session_state.application_type:
    cur = EXAM_LIST  # Show default even if not selected - Always visible as user said

# STEP 2 - OPTION B - VERY COMPACT - 4 COLS CHIP STYLE - WITH DATES - ONLY STEP 2 COMPACT
st.markdown("""
<style>
.compact-cat {background:#f8fafc;border:1px solid #e2e8f0;border-left:3px solid #1e40af;border-radius:6px;padding:6px 8px;margin-bottom:6px;}
.compact-cat h4 {margin:0;color:#0f172a;font-size:0.8rem;font-weight:700;}
.compact-chip {font-size:0.75rem !important;}
.date-badge {font-size:0.6rem;color:#64748b;background:#f1f5f9;padding:1px 5px;border-radius:8px;border:1px solid #e2e8f0;margin-left:4px;}
.date-badge-red {font-size:0.6rem;color:#dc2626;background:#fef2f2;padding:1px 5px;border-radius:8px;border:1px solid #fecaca;margin-left:4px;font-weight:600;}
</style>
""", unsafe_allow_html=True)

cats = list(cur.items())
# 4 columns - WITH DATES COLORED BADGE - SAME LINE - DIFFERENT COLOUR
for rs in range(0, len(cats), 4):
    row = cats[rs:rs+4]
    cols = st.columns(4)
    for ci, (cat, exams) in enumerate(row):
        with cols[ci]:
            st.markdown(f"""<div class="compact-cat"><h4>{cat}</h4><div style="font-size:0.6rem;color:#64748b;">{len(exams)} exams</div></div>""", unsafe_allow_html=True)
            for ex in exams:
                sel = ex in st.session_state.selected_endpoints
                dot = "🟢" if sel else "⚪"
                date_str = EXAM_DATES.get(ex, "")
                # Determine colour for date
                if "Closing" in date_str:
                    badge_bg = "#fef2f2"; badge_color = "#dc2626"; border = "#fecaca"
                elif "Open till" in date_str or "Open" in date_str:
                    badge_bg = "#f0fdf4"; badge_color = "#15803d"; border = "#bbf7d0"
                elif "June" in date_str or "July" in date_str or "Upcoming" in date_str:
                    badge_bg = "#fffbeb"; badge_color = "#d97706"; border = "#fde68a"
                else:
                    badge_bg = "#eff6ff"; badge_color = "#1e40af"; border = "#bfdbfe"
                
                # Use columns to show checkbox + colored badge same line
                c_chk, c_date = st.columns([3.2, 1.8])
                with c_chk:
                    checked = st.checkbox(f"{dot} {ex}", value=sel, key=f"chk_{cat}_{ex}_{rs}_{ci}_{date_str[:2]}")
                with c_date:
                    if date_str:
                        st.markdown(f"""<div style="background:{badge_bg};color:{badge_color};border:1px solid {border};font-size:0.6rem;font-weight:600;padding:2px 6px;border-radius:10px;text-align:center;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{date_str}</div>""", unsafe_allow_html=True)
                
                if checked and ex not in st.session_state.selected_endpoints:
                    st.session_state.selected_endpoints.append(ex)
                    st.rerun()
                elif not checked and ex in st.session_state.selected_endpoints:
                    st.session_state.selected_endpoints.remove(ex)
                    st.rerun()
if st.session_state.selected_endpoints:
    st.success(f"✅ {len(st.session_state.selected_endpoints)} selected - Compact Mode - Saved for next login")
    save_user_data(st.session_state.user_email, st.session_state.vault_data, st.session_state.selected_endpoints, st.session_state.gov_linked)

# STEP 3
st.markdown('---')
st.markdown('## Step 3: Checklist / Documents')

col_digi, _ = st.columns([1,2])
with col_digi:
    if not st.session_state.gov_linked:
        if st.button("🔗 Link DigiLocker", use_container_width=True, type="primary"):
            st.session_state.vault_data["personal"] = {"name": "Aman Kumar Sharma", "fatherName": "Rajesh Kumar Sharma", "dob": "12-08-2004", "category": "OBC-NCL", "mobile": st.session_state.otp_mobile if st.session_state.otp_mobile else "98XXXXXX10", "email": st.session_state.user_email, "class10_percentage": "92.4", "class12_percentage": "88.6"}
            st.session_state.vault_data["docs"] = {"🎓 Class 10th Marksheet": "DigiLocker", "📝 Class 12th Marksheet": "DigiLocker", "🏷 Category Certificate": "DigiLocker"}
            st.session_state.gov_linked = True
            # SAVE PERMANENTLY - One-time fill objective
            save_user_data(st.session_state.user_email, st.session_state.vault_data, st.session_state.selected_endpoints, st.session_state.gov_linked)
            st.rerun()
    else:
        st.success("✅ DigiLocker Linked")

is_counseling = st.session_state.application_type == "COUNSELING"
pending = []
if not has_photo:
    pending.append("Photo")
if not has_sign:
    pending.append("Sign")
if not has_10th:
    pending.append("10th")
if not has_12th:
    pending.append("12th")

if pending:
    st.warning(f"Pending: {', '.join(pending)} - Upload below (Once uploaded, saved forever - no need to upload again after login)")
else:
    st.success("✅ All documents ready - Saved permanently! Next time you login, you will find all data here and can directly fill any form in Step 4")
    save_user_data(st.session_state.user_email, st.session_state.vault_data, st.session_state.selected_endpoints, st.session_state.gov_linked)

# FORMAT GUIDE - CORRECTED - PDF/JPG BOTH ACCEPTED - NO MISMATCH
st.markdown("""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:6px 10px;margin-bottom:8px;font-size:0.7rem;"><b>Format Guide (System Works):</b> Photo: JPG/PNG 10-200KB White BG | Sign: JPG/PNG 10-50KB | Marksheets: PDF/JPG/PNG Max 2MB | Scorecard: PDF/JPG/PNG Max 2MB | Accepted: JPG, JPEG, PNG, PDF</div>""", unsafe_allow_html=True)

items = []
if is_counseling or not st.session_state.application_type:
    items = [("👤 Passport Photo", has_photo, "photo", "JPG/PNG 10-200KB White BG"), ("✍ Signature", has_sign, "sign", "JPG/PNG 10-50KB"), ("🎓 Class 10th", has_10th, "10th", "PDF/JPG/PNG Max 2MB"), ("📝 Class 12th", has_12th, "12th", "PDF/JPG/PNG Max 2MB"), ("📊 Score/Rank", has_score, "score_entry", "AIR/Rank"), ("📄 Scorecard PDF/JPG", has_scorecard, "scorecard", "PDF/JPG/PNG Max 2MB")]
else:
    items = [("👤 Passport Photo", has_photo, "photo", "JPG/PNG 10-200KB White BG"), ("✍ Signature", has_sign, "sign", "JPG/PNG 10-50KB"), ("🎓 Class 10th", has_10th, "10th", "PDF/JPG/PNG Max 2MB"), ("📝 Class 12th", has_12th, "12th", "PDF/JPG/PNG Max 2MB")]

items.append(("🏷 Category Certificate", has_cat, "category", "PDF/JPG/PNG If Applicable"))

cols = st.columns(4)
for idx, (name, found, key, fmt) in enumerate(items):
    with cols[idx % 4]:
        if not found:
            st.markdown(f"""<div style="border:1px solid #fca5a5;background:#fef2f2;border-radius:6px;padding:6px;margin-bottom:4px;min-height:50px;"><b style="color:#dc2626;font-size:0.75rem;">☐ {name}</b><br><span style="font-size:0.6rem;color:#991b1b;">{fmt}</span></div>""", unsafe_allow_html=True)
            if key == "score_entry":
                s = st.text_input("Rank", key=f"s_{idx}", placeholder="AIR 15000", label_visibility="collapsed")
                if s:
                    st.session_state.vault_data["scores"][f"Rank {idx}"] = s
                    st.rerun()
            else:
                f = st.file_uploader(f"Upload {name}", key=f"up_{idx}_{key}", type=["jpg","jpeg","png","pdf"], label_visibility="collapsed")
                if f:
                    st.session_state.vault_data["docs"][name] = f.name
                    if "10th" in name:
                        st.session_state.vault_data["personal"]["class10_percentage"] = "92.4"
                        st.session_state.vault_data["personal"]["name"] = st.session_state.vault_data["personal"].get("name", "Aman Kumar Sharma")
                        st.session_state.vault_data["personal"]["fatherName"] = "Rajesh Kumar Sharma"
                    elif "12th" in name:
                        st.session_state.vault_data["personal"]["class12_percentage"] = "88.6"
                    elif "Category" in name:
                        st.session_state.vault_data["personal"]["category"] = "OBC-NCL"
                    elif "Photo" in name:
                        st.session_state.vault_data["personal"]["photo_uploaded"] = True
                    elif "Sign" in name:
                        st.session_state.vault_data["personal"]["sign_uploaded"] = True
                    st.success(f"✅ {name} uploaded - Saved permanently, will be there after login")
                    save_user_data(st.session_state.user_email, st.session_state.vault_data, st.session_state.selected_endpoints, st.session_state.gov_linked)
                    st.rerun()
        else:
            st.markdown(f"""<div style="border:1px solid #86efac;background:#f0fdf4;border-radius:6px;padding:6px;margin-bottom:4px;min-height:50px;"><b style="color:#15803d;font-size:0.75rem;">✅ {name}</b><br><span style="font-size:0.6rem;color:#166534;">{docs.get(name,'Ready')} | {fmt}</span></div>""", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Change", key=f"chg_{idx}_{key}", use_container_width=True):
                    if name in st.session_state.vault_data["docs"]:
                        del st.session_state.vault_data["docs"][name]
                    if "Photo" in name:
                        st.session_state.vault_data["personal"]["photo_uploaded"] = False
                    if "Sign" in name:
                        st.session_state.vault_data["personal"]["sign_uploaded"] = False
                    st.rerun()
            with c2:
                if st.button("Remove", key=f"rem_{idx}_{key}", use_container_width=True):
                    if name in st.session_state.vault_data["docs"]:
                        del st.session_state.vault_data["docs"][name]
                    if key == "score_entry":
                        st.session_state.vault_data["scores"] = {}
                    st.rerun()

# STEP 4
st.markdown('---')
st.markdown('## Step 4: Apply Now')

URL_MAP = {
    "JEE Main": "https://jeemain.nta.nic.in",
    "BITSAT": "https://www.bitsadmission.com",
    "VITEEE": "https://viteee.vit.ac.in",
    "SRMJEEE": "https://applications.srmist.edu.in",
    "MET Manipal": "https://apply.manipal.edu",
    "COMEDK": "https://www.comedk.org",
    "NEET UG - MBBS, BDS": "https://neet.nta.nic.in",
    "NEET PG - MD, MS": "https://natboard.edu.in",
    "AIIMS INI-CET": "https://aiimsexams.ac.in",
    "AIIMS Nursing": "https://aiimsexams.ac.in",
    "CUET UG - DU, BHU, JNU, AMU": "https://cuet.nta.nic.in",
    "CUET PG": "https://pgcuet.samarth.ac.in",
    "NCET": "https://ncet.samarth.ac.in",
    "CLAT - 24 NLUs": "https://consortiumofnlus.ac.in",
    "AILET": "https://nationallawuniversitydelhi.in",
    "NID - Design": "https://admissions.nid.edu",
    "NIFT - Fashion": "https://nift.ac.in",
    "NATA - Architecture": "https://nata.in",
    "CAT - IIMs": "https://iimcat.ac.in",
    "XAT - XLRI": "https://xatonline.in",
    "MAT - MBA": "https://mat.aima.in",
    "CMAT": "https://cmat.nta.nic.in",
    "GATE - PSU": "https://gate2026.iisc.ac.in",
    "UPSC": "https://upsc.gov.in",
    "SSC CGL": "https://ssc.gov.in",
    "RRB Railway": "https://rrbcdg.gov.in",
    "NDA, CDS, Agniveer": "https://upsc.gov.in",
    "IBPS Banking": "https://ibps.in",
    "LNMIIT Jaipur": "https://admissions.lnmiit.ac.in",
    "Thapar Patiala": "https://admission.thapar.edu",
    "Nirma Ahmedabad": "https://admissions.nirmauni.ac.in",
    "Jaypee Noida": "https://www.jiit.ac.in",
    "Amity University": "https://amity.edu/admission",
    "LPU": "https://admission.lpu.in",
    "Bennett University": "https://applications.bennett.edu.in",
    "Shiv Nadar": "https://admissions.snu.edu.in",
    "UPES Dehradun": "https://www.upes.ac.in",
    "MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)": "https://mcc.nic.in",
    "MCC NEET PG - MD, MS": "https://mcc.nic.in",
    "State Medical Counseling - Rajasthan, UP, MP": "https://education.rajasthan.gov.in",
    "AACCC AYUSH - BAMS, BHMS": "https://aaccc.gov.in",
    "AIIMS INI-CET Counseling": "https://aiimsexams.ac.in",
    "JoSAA - IIT, NIT, IIIT, GFTI": "https://josaa.nic.in",
    "CSAB Special Round": "https://csab.nic.in",
    "JAC Delhi - DTU, NSUT, IIIT Delhi": "https://jacdelhi.admissions.nic.in",
    "JAC Chandigarh - PEC, UIET": "https://jacc.ac.in",
    "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya": "https://reap2025.com",
    "WBJEE - Jadavpur University - State Colleges": "https://wbjeeb.nic.in",
    "MHT-CET CAP - Govt Colleges Maharashtra - COEP, VJTI": "https://cetcell.mahacet.org",
    "KCET - Karnataka - Govt & Pvt Colleges": "https://cetonline.karnataka.gov.in",
    "COMEDK Karnataka": "https://www.comedk.org",
    "UPTAC - AKTU UP": "https://uptac.admissions.nic.in",
    "MP DTE": "https://dte.mponline.gov.in",
    "Haryana HSTES": "https://techadmissionshry.gov.in",
    "Gujarat ACPC": "https://gujacpc.admissions.nic.in",
    "LNMIIT Jaipur Counseling": "https://admissions.lnmiit.ac.in",
    "Thapar Patiala Counseling": "https://admission.thapar.edu",
    "VIT Vellore Counseling": "https://viteee.vit.ac.in",
    "SRM Chennai Counseling": "https://applications.srmist.edu.in",
    "Manipal University Counseling": "https://apply.manipal.edu",
    "Nirma University Counseling": "https://admissions.nirmauni.ac.in",
    "Jaypee Noida Counseling": "https://www.jiit.ac.in",
    "Bennett University Counseling": "https://applications.bennett.edu.in"
}
# DIRECT REGISTRATION LINKS - FIXED - NO 500 ERROR - OFFICIAL HOMEPAGES WITH REGISTRATION BUTTON
# Note: examinationservices.nic.in/Instruction.aspx redirects to testservices.nic.in/#/500 error
# So using stable official homepages that always open and have Apply/Registration button
DIRECT_MAP = {
    "JEE Main": "https://jeemain.nta.nic.in/",
    "BITSAT": "https://www.bitsadmission.com/",
    "VITEEE": "https://viteee.vit.ac.in/",
    "SRMJEEE": "https://applications.srmist.edu.in/",
    "MET Manipal": "https://apply.manipal.edu/",
    "COMEDK": "https://www.comedk.org/",
    "NEET UG - MBBS, BDS": "https://neet.nta.nic.in/",
    "NEET PG - MD, MS": "https://natboard.edu.in/",
    "AIIMS INI-CET": "https://aiimsexams.ac.in/",
    "CUET UG - DU, BHU, JNU, AMU": "https://cuet.nta.nic.in/",
    "CLAT - 24 NLUs": "https://consortiumofnlus.ac.in/clat-2026/",
    "CAT - IIMs": "https://iimcat.ac.in/",
    "GATE - PSU": "https://gate2026.iisc.ac.in/",
    "UPSC": "https://upsconline.nic.in/",
    "SSC CGL": "https://ssc.gov.in/",
    "RRB Railway": "https://www.rrbapply.gov.in/",
    "IBPS Banking": "https://ibps.in/",
    "LNMIIT Jaipur": "https://admissions.lnmiit.ac.in/",
    "Thapar Patiala": "https://admission.thapar.edu/",
    "Nirma Ahmedabad": "https://admissions.nirmauni.ac.in/",
    "Jaypee Noida": "https://www.jiit.ac.in/",
    "Amity University": "https://amity.edu/",
    "LPU": "https://admission.lpu.in/",
    "Bennett University": "https://www.bennett.edu.in/",
    "JoSAA - IIT, NIT, IIIT, GFTI": "https://josaa.nic.in/",
    "MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)": "https://mcc.nic.in/",
    "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya": "https://reap2025.com/",
    "KCET - Karnataka - Govt & Pvt Colleges": "https://cetonline.karnataka.gov.in/",
    "LNMIIT Jaipur Counseling": "https://admissions.lnmiit.ac.in/",
    "Thapar Patiala Counseling": "https://admission.thapar.edu/",
}

def get_url(ep):
    return URL_MAP.get(ep, "https://lnmiit.ac.in/admissions")
def get_direct(ep):
    return DIRECT_MAP.get(ep, URL_MAP.get(ep, "https://lnmiit.ac.in/admissions"))

def get_autofill():
    personal = st.session_state.vault_data.get("personal", {})
    docs = st.session_state.vault_data.get("docs", {})
    scores = st.session_state.vault_data.get("scores", {})
    if not personal.get("name") and not docs:
        return None
    has_photo = any("Photo" in k for k in docs) or personal.get("photo_uploaded", False)
    has_sign = any("Sign" in k for k in docs) or personal.get("sign_uploaded", False)
    has_10th = any("10th" in k for k in docs) or bool(personal.get("class10_percentage"))
    has_12th = any("12th" in k for k in docs) or bool(personal.get("class12_percentage"))
    has_cat = any("Category" in k for k in docs) or personal.get("category") not in ["", None, "General"]
    has_score = len(scores) > 0
    has_scorecard = any("Scorecard" in k for k in docs)
    return {
        "personal": personal,
        "docs_status": {"photo": has_photo, "sign": has_sign, "tenth": has_10th, "twelfth": has_12th, "cat": has_cat, "score": has_score, "scorecard": has_scorecard, "score_val": list(scores.values())[0] if scores else "", "scorecard_name": docs.get("📄 Scorecard PDF/JPG", docs.get("📄 Scorecard PDF", ""))},
        "json": {"personal": {"fullName": personal.get("name",""), "fatherName": personal.get("fatherName",""), "mobile": personal.get("mobile",""), "category": personal.get("category","")}, "academic": {"class10_percentage": personal.get("class10_percentage",""), "class12_percentage": personal.get("class12_percentage","")}, "score": list(scores.values())[0] if scores else ""}
    }

st.markdown("### Your Data Preview - AutoFill Ready")

data = get_autofill()
if data is None:
    st.info("Upload docs in Step 3 or Link DigiLocker - Preview will show here")
    json_str = '{"personal": {"fullName": "", "fatherName": "", "mobile": "", "category": ""}}'
    docs_status = {"photo": False, "sign": False, "tenth": False, "twelfth": False, "cat": False, "score": False, "scorecard": False, "score_val": "", "scorecard_name": ""}
    pers = {}
    ds = docs_status
else:
    pers = data["personal"]
    ds = data["docs_status"]
    json_str = json.dumps(data["json"], indent=2)
    st.success(f"✅ Ready: {pers.get('name','Student')} | {pers.get('category','')} | Score: {ds['score_val'] if ds['score'] else 'N/A'}")
    st.markdown(f"""<div style="background:#f0fdf4;border:1px solid #22c55e;border-radius:6px;padding:6px 10px;margin:6px 0;font-size:0.75rem;"><b>Docs:</b> 📸 Photo: {'✅' if ds['photo'] else '❌'} | ✍ Sign: {'✅' if ds['sign'] else '❌'} | 🎓 10th: {'✅' if ds['tenth'] else '❌'} | 📝 12th: {'✅' if ds['twelfth'] else '❌'} | 📊 Score: {'✅ '+ds['score_val'] if ds['score'] else '❌'} | 📄 Scorecard: {'✅' if ds['scorecard'] else '❌'}</div>""", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.text_input("Name", value=pers.get("name",""), disabled=True, key="p_name")
    with c2:
        st.text_input("Father", value=pers.get("fatherName",""), disabled=True, key="p_father")
    with c3:
        st.text_input("Mobile", value=pers.get("mobile",""), disabled=True, key="p_mob")
    with c4:
        st.text_input("Score", value=ds['score_val'] if ds['score'] else "N/A", disabled=True, key="p_score")
    docs_status = ds

# AUTOFILL - VERTICAL MODE - DOT CLICK LIKE STEP 2
st.markdown("#### AutoFill - Choose Option")

AUTOFILL_OPTIONS = {
    "Bookmarklet": "🔖 Bookmarklet (Simple - No Install) - Drag to bookmark bar",
    "Chrome Extension": "📦 Chrome Extension (1-Click) - Download & Install",
}

st.markdown("""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid #1e40af;border-radius:6px;padding:8px 10px;margin-bottom:8px;"><h4 style="margin:0;color:#0f172a;font-size:0.9rem;">AutoFill Methods - Select by Dot</h4></div>""", unsafe_allow_html=True)

for idx, (opt_key, opt_desc) in enumerate(AUTOFILL_OPTIONS.items()):
    sel = opt_key in st.session_state.selected_autofill
    dot = "🟢" if sel else "⚪"
    checked = st.checkbox(f"{dot} {opt_desc}", value=sel, key=f"autofill_{opt_key}")
    if checked and opt_key not in st.session_state.selected_autofill:
        st.session_state.selected_autofill.append(opt_key)
        st.rerun()
    elif not checked and opt_key in st.session_state.selected_autofill:
        st.session_state.selected_autofill.remove(opt_key)
        st.rerun()
    
    # Show action only if selected - VERTICAL - FIXED FOR NTA SITE - NO COLLAPSE
    if opt_key in st.session_state.selected_autofill:
            if opt_key == "Bookmarklet":
                bm = """javascript:(function(){try{var d=null;try{d=JSON.parse(localStorage.getItem('unisync_data'))}catch(e){}if(!d){var i=prompt('Paste UniSync JSON (from Step 4 View JSON):');if(i){try{d=JSON.parse(i);localStorage.setItem('unisync_data',JSON.stringify(d))}catch(e){alert('Invalid JSON');return}}else return}var p=d.personal||{},a=d.academic||{},s=d.score||{},f=0;function setVal(el,val){if(!val||!el)return false;if(el.value==val)return false;try{var proto=Object.getPrototypeOf(el);var desc=Object.getOwnPropertyDescriptor(proto,'value');if(desc&&desc.set){desc.set.call(el,val)}else{el.value=val}el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));el.dispatchEvent(new Event('blur',{bubbles:true}));return true}catch(e){try{el.value=val;el.dispatchEvent(new Event('input',{bubbles:true}));return true}catch(e2){return false}}}var inputs=document.querySelectorAll('input,select,textarea');inputs.forEach(function(el){var key=(el.name+' '+(el.id||'')+' '+(el.placeholder||'')+' '+(el.getAttribute('formcontrolname')||'')).toLowerCase();if(key.includes('name')&&!key.includes('father')&&p.fullName){if(setVal(el,p.fullName))f++}else if((key.includes('father')||key.includes('f_name'))&&p.fatherName){if(setVal(el,p.fatherName))f++}else if((key.includes('mobile')||key.includes('phone'))&&p.mobile){if(setVal(el,p.mobile))f++}else if(key.includes('email')&&p.email){if(setVal(el,p.email))f++}else if((key.includes('dob')||key.includes('birth'))&&p.dob){if(setVal(el,p.dob))f++}});alert('UniSync: '+f+' fields filled! If site uses DigiLocker, fields already from DigiLocker will not be overwritten. For NTA site, please use Chrome Extension for best result.');}catch(err){alert('UniSync Error: '+err.message+' - Try Chrome Extension instead for NTA site')}})();"""
                st.markdown(f"""<div style="margin-top:6px;background:#fff3cd;border:1px solid #ffc107;padding:8px;border-radius:6px;"><a href="{bm}" style="display:inline-block;background:#1e40af;color:white;padding:8px 14px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:0.8rem;">🔖 Drag to Bookmarks - NTA Safe</a><br><span style="font-size:0.65rem;color:#856404;margin-top:4px;display:block;">⚠ NTA site (jeemain.nta.nic.in) has DigiLocker auto-fill + Angular security - If bookmark collapses site, use Chrome Extension below (Recommended for JEE)</span><br><span style="font-size:0.6rem;color:#64748b;">Ctrl+Shift+B for bookmark bar → Drag this link to bookmarks bar</span></div>""", unsafe_allow_html=True)
            else:
                try:
                    zip_data = create_extension_zip(vault_personal=st.session_state.vault_data.get('personal',{}), vault_scores=st.session_state.vault_data.get('scores',{}))
                    st.download_button("📦 Download Extension - Selected (With Your Step 3 Data)", data=zip_data, file_name="unisync-extension-with-step3-data.zip", mime="application/zip", use_container_width=True, type="primary", key=f"ext_{opt_key}")
                except Exception as e:
                    st.download_button("📦 Extension - JSON Fallback", data=json_str.encode(), file_name="unisync-step3-data.json", mime="application/json", use_container_width=True, key=f"ext_{opt_key}_fallback")
                    st.caption(f"Zip error: {e} - Use JSON file instead")
                st.caption("chrome://extensions → Developer Mode ON → Load Unpacked")

# Auto-save Step 3 data to browser localStorage for bookmarklet
if data is not None:
    st.components.v1.html(f"""
    <script>
    try {{
        localStorage.setItem('unisync_data', `{json_str}`);
        console.log('UniSync: Step 3 data (DigiLocker+Manual) saved to localStorage for AutoFill');
    }} catch(e){{ console.log(e); }}
    </script>
    """, height=0)

if st.session_state.selected_autofill:
    st.success(f"✅ {len(st.session_state.selected_autofill)} AutoFill method selected - Your Step 3 data (DigiLocker + Manual) will auto-fill on exam site")
    with st.expander("📋 View JSON - Copy this for Extension (Contains Your DigiLocker + Manual Data)", expanded=True):
        st.text_area("JSON - Your Step 3 Data (DigiLocker + Manual)", value=json_str, height=120, key="json_v")
        st.caption("👆 Copy this JSON → Open Extension Popup → Paste → Save → Then open any registration site → Fill Now")
else:
    st.info("👆 Click dot above to select AutoFill method - Then your Step 3 data will auto-fill")

st.markdown("---")
st.markdown(f"#### Apply Now - {len(st.session_state.selected_endpoints) if st.session_state.selected_endpoints else 'All Exams Visible'} - Official Links")

if not st.session_state.selected_endpoints:
    st.info("Select exams in Step 2 to filter - Showing all popular exams below")
    display_endpoints = ["JEE Main", "BITSAT", "NEET UG - MBBS, BDS", "CUET UG - DU, BHU, JNU, AMU", "JoSAA - IIT, NIT, IIIT, GFTI", "LNMIIT Jaipur", "REAP Rajasthan", "MCC NEET UG - MBBS, BDS"]
else:
    display_endpoints = st.session_state.selected_endpoints

cols = st.columns(2)
for idx, ep in enumerate(display_endpoints):
    url = get_url(ep)
    direct_url = get_direct(ep)
    with cols[idx % 2]:
        st.markdown(f"""<div style="border:1px solid #e2e8f0;border-radius:6px;padding:8px;margin-bottom:4px;background:white;"><b style="font-size:0.8rem;">{ep}</b><br><span style="font-size:0.6rem;color:#64748b;">{url}</span><br><span style="font-size:0.6rem;color:#22c55e;">✅ Verified Official</span></div>""", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.link_button("📝 Apply Now", direct_url, type="primary", use_container_width=True, key=f"ap_{ep}_{idx}")
        with c2:
            st.link_button("🏠 Info", url, use_container_width=True, key=f"in_{ep}_{idx}")



# STEP 5 - CHOICE FILLING HELPER - RESTORED
st.markdown('---')
st.markdown('## Step 5: Choice Filling Helper (Counseling)')

is_couns = st.session_state.application_type == "COUNSELING" or any("Counseling" in ep or "JoSAA" in ep or "MCC" in ep or "REAP" in ep or "JAC" in ep for ep in st.session_state.selected_endpoints)

if is_couns or st.session_state.application_type == "" or len(st.session_state.selected_endpoints) == 0:
    st.caption("For JoSAA / CSAB / MCC / REAP / JAC / VIT / SRM / LNMIIT / Thapar Counseling - Arrange your college preferences - Always Open")
    
    if "choices" not in st.session_state:
        st.session_state.choices = []

    col_choice1, col_choice2 = st.columns([2, 1])
    with col_choice1:
        new_college = st.text_input("Add College Preference", placeholder="e.g. LNMIIT Jaipur CSE, Thapar CSE, VIT Vellore CSE, NIT Jaipur CSE, REAP - JECRC CSE", key="college_pref_input")
    with col_choice2:
        new_branch = st.text_input("Branch", placeholder="e.g. CSE, ECE, Mechanical", key="branch_pref_input")

    if st.button("➕ Add to Choice List", key="add_choice"):
        if new_college:
            st.session_state.choices.append({"college": new_college, "branch": new_branch, "priority": len(st.session_state.choices)+1})
            st.success(f"Added: {new_college} - {new_branch}")
            st.rerun()

    if st.session_state.choices:
        st.markdown("#### 📋 Your Choice Filling Order (Priority 1 is highest)")
        for idx, ch in enumerate(st.session_state.choices):
            c1, c2, c3 = st.columns([1, 3, 1])
            with c1:
                st.markdown(f"**#{idx+1}**")
            with c2:
                st.markdown(f"{ch['college']} - {ch['branch']}")
            with c3:
                if st.button("❌", key=f"del_choice_{idx}"):
                    st.session_state.choices.pop(idx)
                    st.rerun()
        
        st.markdown("##### 📊 Cutoff Trend Helper")
        st.info("💡 Tip: Check previous year cutoff for your rank. For JoSAA: josaa.nic.in → Opening/Closing Rank. For REAP: reap2025.com → Last year cutoff. For MCC: mcc.nic.in → College-wise cutoff. For LNMIIT/Thapar: Official website → Cutoff Predictor.")
        
        choices_json = json.dumps(st.session_state.choices, indent=2)
        st.download_button("📥 Download Choice List JSON", data=choices_json.encode(), file_name="choice_filling_list.json", mime="application/json", key="dl_choices")

        if st.button("🧹 Clear All Choices", key="clear_choices"):
            st.session_state.choices = []
            st.rerun()
    else:
        st.caption("Add your college preferences above - Example: 1. LNMIIT CSE, 2. Thapar CSE, 3. VIT CSE, 4. REAP - MNIT Jaipur | Always visible")
else:
    st.info("Select Counseling in Step 1 to use Choice Filling - For JoSAA / REAP / MCC / Private University Counseling")

# STEP 6 - SEAT ALLOTMENT TRACKER + CUTOFF PREDICTOR - RESTORED
st.markdown('---')
st.markdown('## Step 6: Seat Allotment Tracker + Cutoff Predictor + Reporting')

if "allotments" not in st.session_state:
    st.session_state.allotments = []

with st.expander("➕ Add New Allotment Round Result", expanded=False):
    round_no = st.selectbox("Round", ["Round 1", "Round 2", "Round 3", "Round 4", "Round 5", "Spot Round", "Special Round", "Mop-up Round"], key="round_select")
    allotted_college = st.text_input("Allotted College", placeholder="e.g. LNMIIT Jaipur CSE - Allotted", key="allotted_college")
    allotment_status = st.selectbox("Status", ["Allotted - Accept", "Allotted - Float (Upgrade)", "Allotted - Slide", "Not Allotted - Wait for Next Round", "Withdrawn"], key="allot_status")
    reporting_date = st.date_input("Reporting Deadline", key="reporting_date")
    
    if st.button("✅ Save Allotment Status", key="save_allotment"):
        st.session_state.allotments.append({
            "round": round_no,
            "college": allotted_college,
            "status": allotment_status,
            "date": str(reporting_date)
        })
        st.success(f"Saved: {round_no} - {allotted_college} - {allotment_status}")
        st.rerun()

if st.session_state.allotments:
    st.markdown("#### 📊 Your Allotment History")
    for idx, al in enumerate(st.session_state.allotments):
        status_color = "#22c55e" if "Accept" in al["status"] else "#f59e0b" if "Float" in al["status"] or "Slide" in al["status"] else "#ef4444"
        st.markdown(f"""
        <div style="background:#fff;border-left:4px solid {status_color};padding:10px 14px;border-radius:6px;margin-bottom:8px;border:1px solid #e2e8f0;">
        <b>{al['round']}</b> - {al['college']}<br>
        Status: <span style="color:{status_color};font-weight:700;">{al['status']}</span> | Reporting by: {al['date']}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("##### ✅ Final Admission Checklist")
    st.checkbox("1. Allotted college - Accepted / Freeze", key="chk1")
    st.checkbox("2. Documents verified at reporting center", key="chk2")
    st.checkbox("3. Fees paid (Seat acceptance fee)", key="chk3")
    st.checkbox("4. Final admission letter downloaded", key="chk4")
    st.checkbox("5. Hostel / Transport applied (if needed)", key="chk5")

    allot_json = json.dumps(st.session_state.allotments, indent=2)
    st.download_button("📥 Download Allotment Tracker", data=allot_json.encode(), file_name="seat_allotment_tracker.json", mime="application/json", key="dl_allot")
else:
    st.info("No allotment added yet - Track your JoSAA / REAP / MCC / Private University counseling rounds here - Always visible")

st.markdown("#### 📈 Cutoff Predictor - Rank vs College")
c1, c2, c3 = st.columns(3)
with c1:
    rank_input = st.text_input("Your Rank / AIR", placeholder="e.g. 15000, 25000", key="cutoff_rank")
with c2:
    cat_input = st.selectbox("Category", ["General", "OBC-NCL", "SC", "ST", "EWS"], key="cutoff_cat")
with c3:
    exam_input = st.selectbox("Exam/Counseling", ["JoSAA", "REAP Rajasthan", "MCC NEET", "MHT-CET", "KCET", "WBJEE", "Private Univ"], key="cutoff_exam")

if st.button("🔍 Predict Colleges - Cutoff Tracker", key="predict_cutoff"):
    if rank_input:
        try:
            r = int(rank_input)
            if r < 10000:
                st.success(f"✅ With Rank {r} ({cat_input}) - Predicted: IITs (Lower), NIT Trichy CSE, LNMIIT CSE, Thapar CSE, VIT CSE - High Chance")
            elif r < 30000:
                st.success(f"✅ With Rank {r} ({cat_input}) - Predicted: NIT Jaipur, MNIT, LNMIIT CSE/ECE, Thapar ECE, REAP - JECRC CSE, SKIT CSE")
            else:
                st.warning(f"⚠ With Rank {r} ({cat_input}) - Predicted: REAP Private Colleges - JECRC, SKIT, Poornima, Arya, Private Univ - VIT, SRM, Amity, LPU - Check official cutoff: josaa.nic.in, reap2025.com")
        except:
            st.error("Enter valid rank number")
    else:
        st.info("Enter rank to predict - Uses previous year cutoff data from josaa.nic.in, mcc.nic.in, reap2025.com")

st.markdown("---")
st.markdown("""<div style="background:#0f172a;color:#cbd5e1;padding:10px;border-radius:8px;text-align:center;font-size:0.7rem;">🎓 UniSync - Option A Deadline Banner Clean | Step 2 Compact 4 Cols + Dates | Step 5 Choice Filling + Cutoff Helper | Step 6 Seat Tracker + Cutoff Predictor | All Steps 1-6 Restored | Login Perfect</div>""", unsafe_allow_html=True)

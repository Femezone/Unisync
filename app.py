"""UniSync - single-file version (all modules merged). Run: streamlit run unisync_single.py"""

# ==================== merged from unisync_vault.py ====================
# Encrypted per-user vault (AES-256-GCM, per-user key derived from a master key).
# Master key: UNISYNC_MASTER_KEY in the environment or Streamlit secrets; base64 of 32 random bytes.
# Generate one: py -c "import base64,secrets;print(base64.b64encode(secrets.token_bytes(32)).decode())"

import os, json, base64, binascii, hashlib, shutil
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

DATA_DIR = os.environ.get("UNISYNC_DATA_DIR", "data")


def _master():
    k = os.environ.get("UNISYNC_MASTER_KEY")
    if not k:
        try:
            k = st.secrets.get("UNISYNC_MASTER_KEY")
        except FileNotFoundError:
            k = None
    if not k:
        raise RuntimeError("UNISYNC_MASTER_KEY is not configured.")
    try:
        key = base64.b64decode(k, validate=True)
    except (binascii.Error, ValueError) as e:
        raise RuntimeError("UNISYNC_MASTER_KEY must be base64-encoded 32 random bytes.") from e
    if len(key) != 32:
        raise RuntimeError("UNISYNC_MASTER_KEY must be base64-encoded 32 random bytes.")
    return key


def user_id(identity: str) -> str:
    """Stable id from verified email/phone. Use the id from st.login() when available."""
    return hashlib.sha256(identity.strip().lower().encode()).hexdigest()


def _user_key(uid: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"unisync-user:" + uid.encode()).derive(_master())


def _dir(uid):
    return os.path.join(DATA_DIR, uid)


def _enc(uid, plaintext: bytes, label: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(_user_key(uid)).encrypt(nonce, plaintext, label.encode())


def _dec(uid, blob: bytes, label: str) -> bytes:
    return AESGCM(_user_key(uid)).decrypt(blob[:12], blob[12:], label.encode())


def _write(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_user_data(identity, vault_data, selected_endpoints, gov_linked) -> bool:
    try:
        uid = user_id(identity)
        payload = {"vault_data": vault_data, "selected_endpoints": selected_endpoints,
                   "gov_linked": gov_linked, "saved_at": datetime.now().isoformat()}
        _write(os.path.join(_dir(uid), "profile.bin"),
               _enc(uid, json.dumps(payload, ensure_ascii=False).encode(), "profile"))
        return True
    except Exception as e:
        print(f"Vault save error: {type(e).__name__}")   # never log the data itself
        return False


def load_user_data(identity):
    try:
        uid = user_id(identity)
        p = os.path.join(_dir(uid), "profile.bin")
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return json.loads(_dec(uid, f.read(), "profile"))
    except Exception as e:
        print(f"Vault load error: {type(e).__name__}")
        return None


def _safe(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:80]


def save_file(identity, key, data: bytes, original_name=""):
    uid = user_id(identity)
    _write(os.path.join(_dir(uid), f"file_{_safe(key)}.bin"),
           _enc(uid, data, "file:" + _safe(key)))
    return True


def load_file(identity, key):
    uid = user_id(identity)
    p = os.path.join(_dir(uid), f"file_{_safe(key)}.bin")
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        return _dec(uid, f.read(), "file:" + _safe(key))


def delete_file(identity, key):
    p = os.path.join(_dir(user_id(identity)), f"file_{_safe(key)}.bin")
    if os.path.exists(p):
        os.remove(p)


def export_user_data(identity):
    """For 'Download my data' (DPDP Act)."""
    return load_user_data(identity)


def delete_user_data(identity):
    """For 'Delete my data' (DPDP Act): removes profile and all files."""
    d = _dir(user_id(identity))
    if os.path.isdir(d):
        shutil.rmtree(d)
        return True
    return False


# ==================== merged from unisync_auth.py ====================
# Secure OTP helpers + input safety. Plug a real SMS/email provider into send_otp().
import os, secrets, hmac, hashlib, time, html, re

OTP_TTL = 300          # 5 minutes
MAX_ATTEMPTS = 5
RESEND_GAP = 30        # seconds
_PEPPER = os.environ.get("UNISYNC_OTP_PEPPER", "change-me").encode()


def esc(x) -> str:
    """Use on every user-supplied value placed inside unsafe_allow_html strings."""
    return html.escape(str(x), quote=True)


def valid_mobile(m: str) -> bool:
    return bool(re.fullmatch(r"[6-9]\d{9}", m or ""))


def _h(mobile, otp):
    return hmac.new(_PEPPER, f"{mobile}:{otp}".encode(), hashlib.sha256).hexdigest()


def issue_otp(state, mobile):
    """state = st.session_state (or a DB row). Returns (ok, message_or_otp_for_sender)."""
    now = time.time()
    if now - state.get("otp_issued", 0) < RESEND_GAP:
        return False, "Please wait before requesting another OTP."
    otp = f"{secrets.randbelow(1_000_000):06d}"
    state.update(otp_hash=_h(mobile, otp), otp_mobile=mobile, otp_issued=now, otp_tries=0)
    return True, otp


def send_otp(mobile, otp):
    """Replace with MSG91 / Twilio Verify. Dev mode only prints to server console."""
    if os.environ.get("UNISYNC_DEV") == "1":
        print(f"[DEV] OTP for {mobile}: {otp}")
        return True
    raise NotImplementedError("Connect an SMS provider (MSG91/Twilio Verify) here.")


def check_otp(state, mobile, entered):
    if state.get("otp_tries", 0) >= MAX_ATTEMPTS:
        return False, "Too many attempts. Request a new OTP."
    if time.time() - state.get("otp_issued", 0) > OTP_TTL:
        return False, "OTP expired."
    state["otp_tries"] = state.get("otp_tries", 0) + 1
    if state.get("otp_mobile") == mobile and hmac.compare_digest(state.get("otp_hash", ""), _h(mobile, entered or "")):
        state.pop("otp_hash", None)
        return True, "OK"
    return False, "Wrong OTP."


# ==================== merged from unisync_images.py ====================
# Upload validation + portal image processing (fixes crop/padding/size logic).
import io
from PIL import Image, ImageOps

Image.MAX_IMAGE_PIXELS = 40_000_000       # block decompression bombs
MAX_UPLOAD = 2 * 1024 * 1024


def sniff(data: bytes):
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def validate_upload(data: bytes, allow=("jpg", "png", "webp", "pdf"), max_bytes=MAX_UPLOAD):
    """Trust file content, not the browser-supplied MIME type."""
    if len(data) > max_bytes:
        return None, f"File too large (max {max_bytes // 1024 // 1024} MB)"
    kind = sniff(data)
    if kind not in allow:
        return None, "Unsupported or corrupted file"
    if kind != "pdf":
        try:
            Image.open(io.BytesIO(data)).verify()
        except Exception:
            return None, "Corrupted image"
    return kind, "OK"


def _flatten(img):
    if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
        img = img.convert("RGBA")
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[-1])
        return bg
    return img.convert("RGB")


def _encode(img, max_bytes):
    for q in range(95, 14, -5):
        b = io.BytesIO()
        img.save(b, "JPEG", quality=q, optimize=True)
        if b.tell() <= max_bytes:
            return b.getvalue(), q
    b = io.BytesIO()
    img.save(b, "JPEG", quality=15, optimize=True)
    return b.getvalue(), 15


def process_portal_image(data: bytes, target_w, target_h, min_kb, max_kb, is_signature=False):
    """Returns (jpeg_bytes | None, message, size). Photo = center crop. Signature = fit + white padding (no ink cut)."""
    try:
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(data)))
        img = _flatten(img)
        if is_signature:
            img = ImageOps.contain(img, (target_w, target_h), Image.LANCZOS)
            canvas = Image.new("RGB", (target_w, target_h), (255, 255, 255))
            canvas.paste(img, ((target_w - img.width) // 2, (target_h - img.height) // 2))
            img = canvas
        else:
            img = ImageOps.fit(img, (target_w, target_h), Image.LANCZOS, centering=(0.5, 0.4))
        out, q = _encode(img, max_kb * 1024)
        if len(out) > max_kb * 1024:
            return None, f"Cannot reach {max_kb}KB - try a simpler image", 0
        if len(out) < min_kb * 1024:
            # portals reject too-small files: embed harmless JPEG comment padding to reach min size
            pad = min_kb * 1024 - len(out) + 64
            b = io.BytesIO()
            img.save(b, "JPEG", quality=q, optimize=True, comment=b"0" * min(pad, 60000))
            out = b.getvalue()
            if not (min_kb * 1024 <= len(out) <= max_kb * 1024):
                return None, "Could not meet minimum size", 0
        return out, f"Ready: {len(out)/1024:.1f}KB ({target_w}x{target_h}) Q{q}", len(out)
    except Exception as e:
        return None, f"Error: {type(e).__name__} - try another image", 0


# ==================== merged from unisync_extension.py ====================
# Click-only Chrome extension (no content_scripts, no <all_urls>, allowlisted sites, paste+save popup).
import io, json, zipfile

ALLOWED_HOSTS = ["nta.nic.in", "josaa.nic.in", "mcc.nic.in", "csab.nic.in", "reap2025.com",
                 "lnmiit.ac.in", "thapar.edu", "viteee.vit.ac.in", "ssc.gov.in", "upsconline.nic.in",
                 "ibps.in", "iimcat.ac.in", "consortiumofnlus.ac.in", "bitsadmission.com"]

POPUP_HTML = """<!doctype html><html><body style="width:300px;padding:10px;font-family:sans-serif">
<h3 style="margin:0 0 6px">UniSync AutoFill</h3>
<textarea id="data" rows="7" style="width:100%" placeholder="Paste JSON from UniSync Step 4"></textarea>
<div style="margin-top:6px"><button id="save">Save Data</button> <button id="fill">Fill Now</button></div>
<div id="msg" style="margin-top:6px;font-size:12px"></div><script src="popup.js"></script></body></html>"""

POPUP_JS = r"""
const ALLOWED = __ALLOWED__;
const $ = id => document.getElementById(id);
const msg = t => { $('msg').textContent = t; };

chrome.storage.local.get(['unisync_data'], r => { if (r.unisync_data) $('data').value = r.unisync_data; });

$('save').onclick = () => {
  try { JSON.parse($('data').value); } catch (e) { return msg('Invalid JSON'); }
  chrome.storage.local.set({ unisync_data: $('data').value }, () => msg('Saved'));
};

$('fill').onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = '';
  try { host = new URL(tab.url).hostname; } catch (e) {}
  if (!ALLOWED.some(d => host === d || host.endsWith('.' + d))) return msg('Site not supported: ' + host);
  const { unisync_data } = await chrome.storage.local.get('unisync_data');
  if (!unisync_data) return msg('Save data first');
  const res = await chrome.scripting.executeScript({
    target: { tabId: tab.id }, func: fillForm, args: [JSON.parse(unisync_data)]
  });
  msg((res[0].result || 0) + ' fields filled. Please review before submitting.');
};

// Runs inside the page only after the user clicks "Fill Now".
function fillForm(D) {
  const P = D.personal || {}, A = D.academic || {};
  const RULES = [
    ['fullName',   /(candidate.?name|full.?name|applicant.?name|student.?name|^name$)/, /(father|mother|guardian|user|college|school|board|institute)/],
    ['fatherName', /(father|f_name|fathername)/, /(occupation|mobile|phone|income)/],
    ['motherName', /(mother|m_name|mothername)/, /(occupation|mobile|phone|income)/],
    ['roll_no',     /(roll.?no|roll.?number|registration.?no|registration.?number)/, null],
    ['mobile',     /(mobile|phone|contact.?no)/, /(parent|father|mother|guardian|alternate|emergency)/],
    ['email',      /(e-?mail)/, /(parent|father|mother|guardian|alternate)/],
    ['dob',        /(dob|birth)/, /(place|state|city|country)/],
    ['category',   /(category|caste)/, /(sub|certificate|number|no$)/],
    ['score',      /(rank|score|air)/, /(category|cut.?off)/],
    ['class10_percentage', /(10th|tenth|class.?x\b|secondary).*(percent|marks|%)|(percent|marks|%).*(10th|tenth|secondary)/, null],
    ['class12_percentage', /(12th|twelfth|class.?xii|senior.?secondary).*(percent|marks|%)|(percent|marks|%).*(12th|twelfth)/, null],
  ];
  const VAL = { fullName: P.fullName, fatherName: P.fatherName, motherName: P.motherName, mobile: P.mobile,
                email: P.email, dob: P.dob, category: P.category, roll_no: P.roll_no,
                score: D.score, class10_percentage: A.class10_percentage,
                class12_percentage: A.class12_percentage };

  function labelText(el) {
    let t = '';
    if (el.id) { const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]'); if (l) t += l.innerText; }
    const p = el.closest('label'); if (p) t += ' ' + p.innerText;
    return t;
  }
  function visible(el) { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; }
  function fmtDate(el, v) {            // v is DD-MM-YYYY
    const m = String(v).match(/^(\d{2})[-\/](\d{2})[-\/](\d{4})$/); if (!m) return v;
    if (el.type === 'date') return m[3] + '-' + m[2] + '-' + m[1];
    const ph = (el.placeholder || '').toLowerCase();
    if (ph.startsWith('yyyy')) return m[3] + '-' + m[2] + '-' + m[1];
    return m[1] + '-' + m[2] + '-' + m[3];
  }
  function setVal(el, v) {
    if (el.tagName === 'SELECT') {
      const want = String(v).toLowerCase().replace(/[^a-z0-9]/g, '');
      const opt = Array.from(el.options).find(o => {
        const a = o.text.toLowerCase().replace(/[^a-z0-9]/g, ''), b = o.value.toLowerCase().replace(/[^a-z0-9]/g, '');
        return a === want || b === want || (want.length > 2 && (a.includes(want) || want.includes(a) && a.length > 2));
      });
      if (!opt) return false;
      el.value = opt.value;
    } else {
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
    }
    ['input', 'change', 'blur'].forEach(e => el.dispatchEvent(new Event(e, { bubbles: true })));
    el.style.outline = '2px solid #22c55e';
    return true;
  }

  let n = 0;
  document.querySelectorAll('input, textarea, select').forEach(el => {
    const type = (el.type || '').toLowerCase();
    if (['hidden', 'password', 'file', 'checkbox', 'radio', 'submit', 'button'].includes(type)) return;
    if (el.disabled || el.readOnly || !visible(el)) return;
    if (el.value && el.tagName !== 'SELECT') return;                      // never overwrite what's there
    const key = [el.name, el.id, el.placeholder, el.getAttribute('formcontrolname'), el.getAttribute('aria-label'), labelText(el)]
      .join(' ').toLowerCase();
    for (const [field, inc, exc] of RULES) {
      const v = VAL[field];
      if (!v || !inc.test(key) || (exc && exc.test(key))) continue;
      if (setVal(el, field === 'dob' ? fmtDate(el, v) : v)) n++;
      break;
    }
  });
  const d = document.createElement('div');
  d.textContent = 'UniSync: ' + n + ' fields filled - please review';
  d.style.cssText = 'position:fixed;top:10px;right:10px;background:#22c55e;color:#fff;padding:8px 12px;border-radius:6px;z-index:2147483647;font:12px sans-serif';
  document.body.appendChild(d); setTimeout(() => d.remove(), 3500);
  return n;
}
"""


def create_extension_zip() -> bytes:
    manifest = {
        "manifest_version": 3, "name": "UniSync AutoFill", "version": "2.0",
        "description": "Fills exam/counselling forms only when you click Fill Now, on supported sites.",
        "permissions": ["storage", "activeTab", "scripting"],
        "action": {"default_popup": "popup.html"},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("popup.html", POPUP_HTML)
        zf.writestr("popup.js", POPUP_JS.replace("__ALLOWED__", json.dumps(ALLOWED_HOSTS)))
    return buf.getvalue()


def autofill_json(personal: dict, scores: dict) -> dict:
    """Matches what the extension reads (fixes name/email mismatch). No Aadhaar."""
    return {
        "personal": {"fullName": personal.get("name", ""), "fatherName": personal.get("fatherName", ""),
                     "motherName": personal.get("motherName", ""), "mobile": personal.get("mobile", ""),
                     "email": personal.get("email", ""), "dob": personal.get("dob", ""),
                     "category": personal.get("category", ""), "roll_no": personal.get("roll_no", "")},
        "academic": {"class10_percentage": personal.get("class10_percentage", ""),
                     "class12_percentage": personal.get("class12_percentage", "")},
        "score": list(scores.values())[0] if scores else "",
    }


# ==================== merged from unisync_extract.py ====================
# PDF/image text extraction -> editable, validated fields. Student must confirm before saving.
import io, re
from pathlib import Path


def _tesseract():
    try:
        import pytesseract
    except ImportError as exc:
        raise RuntimeError("OCR package is missing. Install pytesseract from requirements.txt.") from exc

    command = os.environ.get("TESSERACT_CMD") or shutil.which("tesseract")
    if not command and os.name == "nt":
        candidates = (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tesseract-OCR" / "tesseract.exe",
        )
        command = next((str(path) for path in candidates if path.is_file()), None)
    if command:
        pytesseract.pytesseract.tesseract_cmd = command
    try:
        pytesseract.get_tesseract_version()
    except pytesseract.TesseractNotFoundError as exc:
        raise RuntimeError(
            "Tesseract OCR is not installed or not on PATH. Install it or set TESSERACT_CMD."
        ) from exc
    return pytesseract

def _pdf_text(data):
    try:
        import pymupdf
    except ImportError as exc:
        raise RuntimeError("PDF reading support is missing. Install PyMuPDF from requirements.txt.") from exc

    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            return "\n".join(page.get_text("text") or "" for page in list(doc)[:10])
    except Exception as exc:
        raise RuntimeError(f"Could not read this PDF: {exc}") from exc

def _marksheet_ocr_quality(text):
    fields = parse_marksheet(text)
    return sum(
        field in fields
        for field in ("name", "fatherName", "motherName", "roll_no", "dob", "percentage")
    )

def _combine_marksheet_ocr(attempts):
    ranked = sorted(
        attempts,
        key=lambda attempt: (_marksheet_ocr_quality(attempt), len(attempt)),
        reverse=True,
    )
    merged_fields = parse_marksheet(ranked[0]) if ranked else {}
    for attempt in ranked[1:]:
        for field, value in parse_marksheet(attempt).items():
            if field not in merged_fields:
                merged_fields[field] = value

    labels = {
        "name": "Student Name",
        "fatherName": "Father's Name",
        "motherName": "Mother's Name",
        "roll_no": "Roll No",
        "dob": "Date of Birth",
        "percentage": "Percentage",
    }
    normalized_fields = [
        f"{labels[field]}: {merged_fields[field][0]}"
        for field in labels
        if field in merged_fields
    ]
    return "\n".join([*normalized_fields, *(ranked[:1])])

def _pdf_ocr(data):
    try:
        import pymupdf
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise RuntimeError("Scanned PDF support is missing. Install PyMuPDF and Pillow.") from exc

    pytesseract = _tesseract()
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            pages = []
            for page in list(doc)[:10]:
                with Image.open(io.BytesIO(page.get_pixmap(dpi=300).tobytes("png"))) as image:
                    image = ImageOps.autocontrast(ImageOps.grayscale(ImageOps.exif_transpose(image)))
                    attempts = [
                        pytesseract.image_to_string(image, config=f"--oem 3 --psm {mode}")
                        for mode in (6, 11)
                    ]
                    pages.append(_combine_marksheet_ocr(attempts))
            return "\n".join(pages)
    except Exception as exc:
        raise RuntimeError(f"Could not OCR this PDF: {exc}") from exc

def _img_ocr(data):
    try:
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise RuntimeError("Image OCR requires Pillow.") from exc

    pytesseract = _tesseract()
    try:
        with Image.open(io.BytesIO(data)) as image:
            im = ImageOps.autocontrast(ImageOps.grayscale(ImageOps.exif_transpose(image)))
            images = [im]
            if max(im.size) <= 1600:
                images.append(im.resize((im.width * 2, im.height * 2)))
            attempts = [
                pytesseract.image_to_string(candidate, config=f"--oem 3 --psm {mode}")
                for candidate in images
                for mode in (6, 11)
            ]
            return _combine_marksheet_ocr(attempts)
    except Exception as exc:
        raise RuntimeError(f"Could not OCR this image: {exc}") from exc

def extract_text(data: bytes, kind: str):
    if kind == "pdf":
        t = _pdf_text(data)
        text_field_count = sum(not key.startswith("_") for key in parse_marksheet(t))
        if text_field_count >= 4:
            return t, "PDF text"
        try:
            ocr = _pdf_ocr(data)
        except RuntimeError as exc:
            if t.strip():
                return t, f"PDF text (OCR fallback unavailable: {exc})"
            raise
        ocr_field_count = sum(not key.startswith("_") for key in parse_marksheet(ocr))
        if ocr_field_count > text_field_count:
            return ocr, "OCR"
        if t.strip() and ocr.strip():
            return f"{t}\n{ocr}", "PDF text + OCR"
        return (t, "PDF text") if t.strip() else (ocr, "OCR")
    return _img_ocr(data), "ocr"

def parse_marksheet(text: str):
    """Extract marksheet fields from labeled text without treating arbitrary dates as DOB."""
    result = {}

    field_labels = (
        r"candidate(?:'?s)?\s+name", r"name\s+of\s+(?:the\s+)?candidate",
        r"student(?:'?s)?\s+name", r"name\s+of\s+(?:the\s+)?student",
        r"applicant(?:'?s)?\s+name", r"full\s+name", r"नाम",
        r"father(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:./-]+name",
        r"(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?"
        r"\s*/\s*(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:.-]+name",
        r"(?:father|guardian|parent)\s*/\s*(?:father|guardian|parent)\s+name",
        r"name\s+of\s+(?:the\s+)?(?:father|guardian|parent)",
        r"पिता\s*(?:का\s*)?नाम",
        r"mother(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:.-]+name", r"name\s+of\s+(?:the\s+)?mother",
        r"माता\s*(?:का\s*)?नाम",
        r"date\s+of\s+birth", r"birth\s+date", r"d\.?\s*o\.?\s*b\.?", r"जन्म\s*(?:तिथि|दिनांक)",
        r"roll\s*(?:no\.?|number)", r"registration\s*(?:no\.?|number)",
        r"enrol(?:ment)?\s*(?:no\.?|number)",
        r"percentage|aggregate\s+marks|total\s+marks|marks\s+obtained|"
        r"maximum\s+marks|grand\s+total|result\s+total|प्रतिशत|प्राप्तांक|कुल\s+अंक",
    )
    next_label = r"(?:" + "|".join(field_labels) + r")"

    def labeled_value(labels, max_length=100, source=None):
        source = text if source is None else source
        label = r"(?:" + "|".join(labels) + r")"
        pattern = re.compile(
            rf"(?im)(?<!\w)\s*{label}\s*"
            rf"(?::|=|-)?\s*([^\r\n|]{{1,{max_length}}})"
        )
        for match in pattern.finditer(source):
            value = re.split(
                rf"\s{{2,}}|\s+(?={next_label}\b)",
                match.group(1),
                maxsplit=1,
                flags=re.I,
            )[0].strip(" \t:=-.")
            if value:
                return value
        following_line = re.search(
            rf"(?im){label}\s*[:=\-]?\s*\r?\n(?:[ \t]*\r?\n)*[ \t]*"
            rf"([^\r\n|]{{1,{max_length}}})",
            source,
        )
        if following_line:
            value = following_line.group(1).strip(" \t:=-.")
            if not re.match(rf"(?i)^{next_label}\b", value):
                return value
        return ""

    def put(key, value, confidence=0.65):
        value = " ".join(value.split()).strip(" :;,-.")
        if value:
            result[key] = (value, confidence)

    student_name_labels = (
        r"candidate(?:'?s)?\s+name", r"name\s+of\s+(?:the\s+)?candidate",
        r"student(?:'?s)?\s+name", r"name\s+of\s+(?:the\s+)?student",
        r"applicant(?:'?s)?\s+name", r"full\s+name",
        r"अभ्यर्थी\s*का\s*नाम", r"छात्र(?:ा)?\s*का\s*नाम",
        r"विद्यार्थी\s*का\s*नाम",
    )
    name = labeled_value(student_name_labels)
    if not name:
        generic_name_text = re.sub(
            r"(?i)(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?"
            r"[\s:./-]+name|name\s+of\s+(?:the\s+)?(?:father|guardian|parent)"
            r"|पिता\s*(?:का\s*)?नाम",
            "",
            text,
        )
        name = labeled_value((r"\bname\b", r"नाम"), source=generic_name_text)
    if not name:
        heading_words = {
            "ALL", "INDIA", "CENTRAL", "BOARD", "SECONDARY", "SCHOOL",
            "SENIOR", "CERTIFICATE", "EXAMINATION", "MARKS", "STATEMENT",
            "RESULT", "SUBJECT", "CANDIDATE", "STUDENT", "NAME",
        }
        table_header = re.search(r"(?i)\b(?:subject|marks\s+obtained|theory|practical)\b", text)
        name_section = text[:table_header.start()] if table_header else text
        for line in name_section.splitlines():
            tokens = line.strip(" \t:").split()
            normalized_tokens = [token.strip(".,:;") for token in tokens]
            if len(normalized_tokens) != 2:
                continue
            if any(not re.fullmatch(r"[A-Z]{2,}", token) for token in normalized_tokens):
                continue
            if any(token in heading_words for token in normalized_tokens):
                continue
            name = " ".join(normalized_tokens)
            break
    if name.casefold() not in {"लिखित", "written", "name", "student", "candidate"}:
        put("name", name, 0.65)
    put("fatherName", labeled_value((
        r"(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:./-]+name",
        r"(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?"
        r"\s*/\s*(?:father|guardian|parent)(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:.-]+name",
        r"(?:father|guardian|parent)\s*/\s*(?:father|guardian|parent)\s+name",
        r"name\s+of\s+(?:the\s+)?(?:father|guardian|parent)",
        r"पिता\s*(?:का\s*)?नाम",
    )))
    put("motherName", labeled_value((
        r"mother(?:['\u2019\u2018`\u00b4\ufffd]?\s*s)?[\s:.-]+name",
        r"name\s+of\s+(?:the\s+)?mother",
        r"माता\s*(?:का\s*)?नाम",
    )))
    if (
        result.get("name")
        and result.get("fatherName")
        and result["name"][0].casefold() == result["fatherName"][0].casefold()
    ):
        result.pop("name")
    roll_number = labeled_value((
        r"roll\s*(?:no\.?|number)", r"registration\s*(?:no\.?|number)",
        r"enrol(?:ment)?\s*(?:no\.?|number)",
    ), 40).strip(" \t:=-./\\")
    put("roll_no", roll_number, 0.75)

    # A DOB is accepted only when the date is explicitly attached to a birth label.
    dob_value = labeled_value((
        r"date\s+of\s+birth", r"birth\s+date", r"D\.?O\.?B\.?", r"जन्म\s*(?:तिथि|दिनांक)",
    ), 40)
    dob_match = re.search(
        r"\b(\d{1,2})[-/.](\d{1,2})[-/.]((?:19|20)\d{2})\b",
        dob_value,
    )
    if dob_match:
        day, month, year = map(int, dob_match.groups())
        try:
            from datetime import date
            date(year, month, day)
            put("dob", f"{day:02d}-{month:02d}-{year}", 0.85)
        except ValueError:
            pass

    if "dob" not in result and dob_value:
        from datetime import datetime
        for date_format in ("%d %B %Y", "%d %b %Y", "%Y-%m-%d", "%Y/%m/%d"):
            try:
                birth_date = datetime.strptime(dob_value.strip(), date_format)
            except ValueError:
                continue
            put("dob", birth_date.strftime("%d-%m-%Y"), 0.85)
            break

    signature_dates = set()
    date_pattern = re.compile(r"\b(\d{1,2})[-/.](\d{1,2})[-/.]((?:19|20)\d{2})\b")
    signature_contexts = re.finditer(
        r"(?is)(?:digitally\s+signed|digital\s+signature|signature\s+date|signed\s+on)"
        r".{0,120}",
        text,
    )
    for context in signature_contexts:
        for signed_date in date_pattern.finditer(context.group()):
            day, month, year = map(int, signed_date.groups())
            try:
                from datetime import date
                date(year, month, day)
            except ValueError:
                continue
            signature_dates.add(f"{day:02d}-{month:02d}-{year}")
    if signature_dates:
        result["_signature_dates"] = (",".join(sorted(signature_dates)), 1.0)

    subject_marks = {}
    non_subject_labels = re.compile(
        r"(?i)^(?:percentage|aggregate|total|grand\s+total|result\s+total|"
        r"marks?\s+(?:obtained|secured|scored)|maximum\s+marks?|"
        r"candidate|student|applicant|father|mother|date\s+of\s+birth|dob)\b"
    )
    for line in text.splitlines():
        ratio = re.match(
            r"^\s*(?:\d{1,3}\s+)?(?P<subject>[A-Za-z][A-Za-z &()./'-]{1,45}?)"
            r"\s*[:\-]?\s+(?P<obtained>\d{1,3})\s*"
            r"(?:/|out\s+of|of)\s*(?P<maximum>\d{1,3})\b",
            line.strip(),
            re.I,
        )
        if not ratio:
            continue
        subject = " ".join(ratio.group("subject").split()).strip(" -:.,")
        if not subject or non_subject_labels.match(subject):
            continue
        obtained, maximum = int(ratio.group("obtained")), int(ratio.group("maximum"))
        if maximum <= 0 or obtained > maximum:
            continue
        subject_marks[subject] = (obtained, maximum)
    if subject_marks:
        result["_subject_marks"] = (
            "; ".join(
                f"{subject}: {obtained}/{maximum}"
                for subject, (obtained, maximum) in sorted(subject_marks.items())
            ),
            1.0,
        )

    number_words = {
        "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
        "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
        "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
        "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
        "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
        "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
        "eighty": 80, "ninety": 90, "hundred": 100,
    }

    def score_from_words(phrase):
        words = re.findall(r"[a-z]+", phrase.casefold())
        if not words or any(word not in number_words and word != "and" for word in words):
            return None
        words = [word for word in words if word != "and"]
        if "hundred" in words:
            index = words.index("hundred")
            hundreds = number_words[words[index - 1]] if index else 1
            return hundreds * 100 + sum(number_words[word] for word in words[index + 1:])
        if len(words) == 2 and number_words[words[0]] >= 20:
            return number_words[words[0]] + number_words[words[1]]
        return sum(number_words[word] for word in words)

    word_scores = []
    table_start = re.search(r"(?i)\b(?:subject|marks\s+obtained)\b", text)
    if table_start:
        table_text = text[table_start.start():]
        table_end = re.search(r"(?i)\b(?:result|abbreviations|dated)\b", table_text)
        if table_end:
            table_text = table_text[:table_end.start()]
        number_word_pattern = re.compile(
            r"\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|"
            r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
            r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|"
            r"eighty|ninety|hundred)(?:[\s-]+|$))+(?<![\s-])",
            re.I,
        )
        for line in table_text.splitlines():
            for match in number_word_pattern.finditer(line.strip()):
                score = score_from_words(match.group().strip())
                if score is not None and 0 <= score <= 100:
                    word_scores.append(score)

    percentage_match = re.search(
        r"(?i)(?:aggregate\s+)?(?:overall\s+)?(?:percentage|percent|marks\s*%|प्रतिशत)[^\d%]{0,30}"
        r"(\d{1,3}(?:\.\d{1,2})?)\s*%?",
        text,
    ) or re.search(r"\b(\d{1,3}(?:\.\d{1,2})?)\s*%", text)
    if percentage_match and 0 < float(percentage_match.group(1)) <= 100:
        put("percentage", percentage_match.group(1), 0.75)
    else:
        totals = re.search(
            r"(?i)(?:aggregate\s+marks?|total\s+marks?|grand\s+total|"
            r"result\s+total|marks\s+obtained|marks\s+secured|प्राप्तांक|कुल\s+अंक)"
            r"[^\d]{0,24}(\d{2,4})\s*(?:/|out\s+of|of)\s*(\d{2,4})",
            text,
        )
        if totals:
            obtained, maximum = map(int, totals.groups())
            if 0 < obtained <= maximum:
                value = f"{obtained / maximum * 100:.2f}".rstrip("0").rstrip(".")
                put("percentage", value, 0.55)
        if "percentage" not in result:
            obtained_match = re.search(
                r"(?i)(?:total\s+)?marks?\s+(?:obtained|secured|scored)"
                r"[^\d]{0,15}(\d{2,4})",
                text,
            )
            maximum_match = re.search(
                r"(?i)(?:maximum|max\.?)\s+marks?"
                r"[^\d]{0,15}(\d{2,4})",
                text,
            )
            if obtained_match and maximum_match:
                obtained, maximum = map(
                    int,
                    (obtained_match.group(1), maximum_match.group(1)),
                )
                if 0 < obtained <= maximum:
                    value = f"{obtained / maximum * 100:.2f}".rstrip("0").rstrip(".")
                    put("percentage", value, 0.55)
    if "percentage" not in result and len(subject_marks) >= 5:
        best_five_marks = sorted(
            subject_marks.values(),
            key=lambda marks: marks[0],
            reverse=True,
        )[:5]
        obtained_total = sum(obtained for obtained, _ in best_five_marks)
        maximum_total = sum(maximum for _, maximum in best_five_marks)
        value = f"{obtained_total / maximum_total * 100:.2f}".rstrip("0").rstrip(".")
        put("percentage", value, 0.5)
    elif "percentage" not in result and len(word_scores) >= 5:
        best_five_scores = sorted(word_scores, reverse=True)[:5]
        value = f"{sum(best_five_scores) / 500 * 100:.2f}".rstrip("0").rstrip(".")
        put("percentage", value, 0.5)
    return result


# ==================== app ====================
import streamlit as st
import json
import os
import secrets
import hmac
import sqlite3


st.set_page_config(page_title="UniSync - One Stop Solution", page_icon="🎓", layout="wide", initial_sidebar_state="collapsed")

DEV_MODE = os.environ.get("UNISYNC_DEV") == "1"
AUTH_DB = os.environ.get("UNISYNC_AUTH_DB", os.path.join(DATA_DIR, "accounts.sqlite3"))
try:
    _master()
except RuntimeError as e:
    VAULT_READY = False
    VAULT_KEY_ERROR = str(e)
else:
    VAULT_READY = True
    VAULT_KEY_ERROR = ""

_defaults = {
    "logged_in": False, "user_email": "", "user_name": "",
    "vault_identity": "",
    "vault_data": {"personal": {}, "docs": {}, "scores": {}, "credentials": {}},
    "selected_endpoints": [], "application_type": "", "gov_linked": False,
    "otp_sent": False, "otp_mobile": "", "selected_autofill": [],
}
for _k, _v in _defaults.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


def persist():
    """Save to the encrypted vault - only with consent and only if the vault key is configured."""
    if st.session_state.get("consent") and VAULT_READY:
        save_user_data(st.session_state.get("vault_identity") or st.session_state.user_email,
                       st.session_state.vault_data,
                       st.session_state.selected_endpoints, st.session_state.gov_linked)


def finish_login(email, name, vault_identity=None):
    st.session_state.logged_in = True
    st.session_state.user_email = email
    st.session_state.user_name = name
    identity = vault_identity or email
    st.session_state.vault_identity = identity
    saved = load_user_data(identity) if VAULT_READY else None
    if saved:
        st.session_state.vault_data = saved["vault_data"]
        st.session_state.selected_endpoints = saved.get("selected_endpoints", [])
        st.session_state.gov_linked = saved.get("gov_linked", False)
        st.session_state.consent = True


def _normalize_account_email(email):
    normalized = email.strip().casefold()
    if (len(normalized) > 254 or normalized.count("@") != 1
            or any(character.isspace() for character in normalized)):
        return None
    local, domain = normalized.rsplit("@", 1)
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return None
    return normalized


def _password_digest(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=1 << 14, r=8, p=1,
        dklen=64, maxmem=64 * 1024 * 1024,
    )


def _initialize_password_db():
    os.makedirs(os.path.dirname(os.path.abspath(AUTH_DB)), exist_ok=True)
    connection = sqlite3.connect(AUTH_DB, timeout=10)
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS password_accounts (
                email TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
    finally:
        connection.close()


def register_password_account(email, password):
    normalized = _normalize_account_email(email)
    if not normalized:
        return False, "Enter a valid email address."
    if len(password) < 12:
        return False, "Use a password with at least 12 characters."
    if len(password) > 1024:
        return False, "Password must be 1024 characters or fewer."

    _initialize_password_db()
    salt = secrets.token_bytes(16)
    password_hash = _password_digest(password, salt)
    connection = sqlite3.connect(AUTH_DB, timeout=10)
    try:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO password_accounts "
            "(email, salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (normalized, salt, password_hash, datetime.now().isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    if cursor.rowcount == 0:
        return False, "An account with that email already exists. Try logging in."
    return True, normalized


def authenticate_password_account(email, password):
    normalized = _normalize_account_email(email)
    if not normalized or not password or len(password) > 1024:
        return None

    _initialize_password_db()
    connection = sqlite3.connect(AUTH_DB, timeout=10)
    try:
        account = connection.execute(
            "SELECT salt, password_hash FROM password_accounts WHERE email = ?",
            (normalized,),
        ).fetchone()
    finally:
        connection.close()

    salt = account[0] if account else b"\0" * 16
    expected_hash = account[1] if account else b"\0" * 64
    actual_hash = _password_digest(password, salt)
    if account and hmac.compare_digest(actual_hash, expected_hash):
        return normalized
    return None


# ---------------- SCHOLARSHIP DATA ----------------
SCHOLARSHIP_SIDEBAR = {
    "JEE Main": ["NSP Central Scholarship (₹50k/year) - 31 Dec - scholarships.gov.in", "JEE Advanced Fee Waiver for SC/ST", "State EWS Scholarship", "TFWS - Tuition Fee Waiver"],
    "BITSAT": ["BITS Merit Scholarship 25%-100%", "MCN - Merit Cum Need (Upto 80%)", "Bihar Student Credit Card"],
    "NEET UG - MBBS, BDS": ["NSP - Central Sector", "State Medical Scholarship (Rajasthan: ₹25k)", "AIIMS Stipend ₹500/month", "PMSSS for J&K"],
    "CUET UG - DU, BHU, JNU, AMU": ["DU Merit Scholarship", "BHU Merit Scholarship ₹3k/month", "JNU MCM Scholarship", "NSP - Post Matric"],
    "JoSAA - IIT, NIT, IIIT, GFTI": ["IIT MCM (Upto ₹1L/year)", "NIT Merit Scholarship", "TFWS - Supernumerary", "National Fellowship SC/ST"],
    "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya": ["Rajasthan Samaj Kalyan Scholarship (SC/ST/OBC) ₹25k-50k", "TFWS Rajasthan - Free Tuition", "LNMIIT Merit 25%-100% (JEE Rank based)", "JECRC Merit Scholarship ₹20k-40k"],
    "LNMIIT Jaipur": ["LNMIIT Merit Scholarship: JEE Rank <15k = 100% fee waiver, <25k = 50%, <40k = 25%", "BPL Scholarship 100%", "Vijay Bhatia Merit"],
    "Thapar Patiala": ["Thapar Merit-Cum-Means (Upto 100%)", "Alumni Scholarship", "Punjab State Scholarship"],
    "DEFAULT": ["NSP - National Scholarship Portal (scholarships.gov.in) - Central", "State Samaj Kalyan Scholarship (SC/ST/OBC) - Upto ₹50k", "TFWS - Tuition Fee Waiver Scheme - All India"]
}

SCHOLARSHIP_UG = [
    {"name": "NSP - Central Sector Scholarship", "amount": "₹10,000-50,000/year", "deadline": "31 Dec 2025", "link": "https://scholarships.gov.in", "desc": "For all UG students - Merit based, Family income < ₹8L", "type": "Central Govt"},
    {"name": "PM Vidya Lakshmi - Education Loan", "amount": "Upto ₹10 Lakhs - No Collateral", "deadline": "Open Year-Round", "link": "https://www.vidyalakshmi.co.in", "desc": "PM Vidya Lakshmi - Education loan for UG/PG in India & Abroad", "type": "PM Scheme"},
    {"name": "PM Vidya Lakshmi - PM USHA Portal", "amount": "Upto ₹10L - Interest Subsidy", "deadline": "Open", "link": "https://pmvidyalaxmi.co.in", "desc": "New PM Vidya Lakshmi Portal - Collateral free loan for top 860 institutions", "type": "PM Scheme"},
    {"name": "Rajasthan Samaj Kalyan - SC/ST/OBC", "amount": "₹25,000-50,000/year", "deadline": "30 Nov 2025", "link": "https://sje.rajasthan.gov.in", "desc": "Rajasthan Social Justice Dept - Post Matric Scholarship", "type": "Rajasthan State"},
    {"name": "Rajasthan - Anuprati Yojana", "amount": "₹50,000-1,00,000", "deadline": "31 Dec 2025", "link": "https://sje.rajasthan.gov.in/Anuprati", "desc": "Rajasthan - Free coaching for JEE, NEET, CLAT, UPSC + Scholarship", "type": "Rajasthan State"},
    {"name": "Rajasthan - Swami Vivekananda Abroad Study", "amount": "Upto ₹20 Lakhs + Airfare", "deadline": "15 Dec 2025", "link": "https://hte.rajasthan.gov.in", "desc": "Rajasthan Govt - Scholarship for abroad UG in top 50 universities (US, UK)", "type": "Rajasthan Abroad"},
    {"name": "Rajasthan - Dr. Ambedkar International", "amount": "Full Tuition + $15,000/year", "deadline": "31 Jan 2026", "link": "https://sje.rajasthan.gov.in", "desc": "Rajasthan SC students for abroad study in US, UK, Australia", "type": "Rajasthan Abroad"},
    {"name": "LNMIIT Jaipur Merit", "amount": "100% waiver if JEE Rank <15k, 50% <25k, 25% <40k", "deadline": "15 Jun 2026", "link": "https://admissions.lnmiit.ac.in/scholarship", "desc": "LNMIIT Jaipur - Merit based on JEE Main rank", "type": "Private Univ"},
    {"name": "VIT Vellore - GVSD", "amount": "25%-100% based on VITEEE rank", "deadline": "31 Mar 2026", "link": "https://viteee.vit.ac.in/scholarship", "desc": "VITEEE rank based scholarship for BTech", "type": "Private Univ"},
    {"name": "Fulbright-Nehru US Undergraduate", "amount": "Full Tuition + Living + Airfare", "deadline": "15 May 2026", "link": "https://www.usief.org.in", "desc": "US-India Educational Foundation - For UG in US", "type": "US Study"},
    {"name": "TFWS - Tuition Fee Waiver", "amount": "100% Tuition Free - All India", "deadline": "Via REAP/JoSAA", "link": "https://www.aicte-india.org", "desc": "AICTE TFWS - 5% supernumerary seats free", "type": "Central"},
    {"name": "Pragati Scholarship for Girls", "amount": "₹50,000/year for girls", "deadline": "31 Dec 2025", "link": "https://scholarships.gov.in", "desc": "AICTE Pragati - Girls in BTech/Diploma", "type": "Girls"},
]

SCHOLARSHIP_PG = [
    {"name": "GATE Scholarship - MTech/ME", "amount": "₹12,400/month for 2 years", "deadline": "Via GATE 2026 Score", "link": "https://gate.iisc.ac.in", "desc": "AICTE GATE Scholarship for MTech in IIT/NIT", "type": "PG - MTech"},
    {"name": "PM Vidya Lakshmi - PG Loan Abroad", "amount": "Upto ₹20 Lakhs for PG Abroad", "deadline": "Open Year-Round", "link": "https://www.vidyalakshmi.co.in", "desc": "PM Vidya Lakshmi - Education loan for PG in India & Abroad - US, UK, Canada", "type": "PM Scheme"},
    {"name": "Fulbright-Nehru Masters Fellowship (US)", "amount": "Full Tuition + Living + Airfare - US PG", "deadline": "15 May 2026", "link": "https://www.usief.org.in/Fulbright-Nehru-Fellowships", "desc": "Top PG scholarship for Indians to do Masters in US - Fully funded", "type": "US PG"},
    {"name": "Chevening Scholarship UK (PG)", "amount": "Full Tuition + Living for UK Masters", "deadline": "05 Nov 2025", "link": "https://www.chevening.org/scholarship/india/", "desc": "UK Govt Chevening - Fully funded Masters in UK", "type": "UK PG"},
    {"name": "Erasmus Mundus EU (PG)", "amount": "€24,000-48,000 for 2 years", "deadline": "15 Jan 2026", "link": "https://erasmus-plus.ec.europa.eu", "desc": "EU Scholarship - Study PG in 2-3 European countries fully funded", "type": "EU PG"},
    {"name": "DAAD Germany (PG)", "amount": "€934/month + Tuition + Airfare", "deadline": "01 Oct 2025", "link": "https://www.daad.org.in", "desc": "Germany DAAD - Masters/PhD in Germany fully funded", "type": "Germany PG"},
    {"name": "Rajasthan - CM Anuprati - PG Abroad", "amount": "Upto ₹20L + Airfare for PG Abroad", "deadline": "31 Dec 2025", "link": "https://hte.rajasthan.gov.in", "desc": "Rajasthan - PG students for abroad in top universities - US/UK", "type": "Rajasthan PG Abroad"},
    {"name": "National Fellowship SC/ST - PG/PhD", "amount": "₹31,000/month + Contingency", "deadline": "31 Dec 2025", "link": "https://scholarships.gov.in", "desc": "UGC - For SC/ST students for PG/PhD in India", "type": "PG - India"},
    {"name": "Prime Minister Research Fellowship (PMRF)", "amount": "₹70,000-80,000/month for PhD", "deadline": "Via GATE/GRE", "link": "https://www.pmrf.in", "desc": "Top PhD fellowship in IITs/IISc", "type": "PhD"},
    {"name": "Stanford Knight-Hennessy PG", "amount": "Full Funding - Stanford PG", "deadline": "09 Oct 2025", "link": "https://knight-hennessy.stanford.edu", "desc": "Fully funded Masters/PhD at Stanford University USA", "type": "US PG"},
    {"name": "Rhodes Scholarship Oxford (PG)", "amount": "Full Tuition + Living - Oxford UK", "deadline": "01 Aug 2026", "link": "https://www.rhodeshouse.ox.ac.uk", "desc": "Most prestigious - Masters/PhD at Oxford UK", "type": "UK PG"},
    {"name": "Inlaks Scholarship - Abroad PG", "amount": "Upto $100,000 for PG Abroad", "deadline": "31 Mar 2026", "link": "https://www.inlaksfoundation.org", "desc": "Inlaks - For Indians to study PG in US/UK/Europe", "type": "Abroad PG"},
]


def get_scholarship_list(selected_list):
    if not selected_list:
        return SCHOLARSHIP_SIDEBAR["DEFAULT"]
    result = []
    for exam in selected_list[:5]:
        if exam in SCHOLARSHIP_SIDEBAR:
            result.append((exam, SCHOLARSHIP_SIDEBAR[exam]))
        else:
            for key in SCHOLARSHIP_SIDEBAR:
                if key.split(" - ")[0].lower() in exam.lower() or exam.lower() in key.lower():
                    result.append((exam, SCHOLARSHIP_SIDEBAR[key]))
                    break
    if not result:
        return [("General", SCHOLARSHIP_SIDEBAR["DEFAULT"])]
    return result


# ---------------- GOOGLE LOGIN RETURN (st.login) ----------------
_u = getattr(st, "user", None)
if not st.session_state.logged_in and _u is not None and getattr(_u, "is_logged_in", False):
    finish_login(_u.email, (_u.get("name") if hasattr(_u, "get") else None) or "Student")

# ---------------- LOGIN ----------------
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
    <div><span style="font-size:0.7rem;background:#eff6ff;color:#1e40af;padding:6px 12px;border-radius:20px;border:1px solid #bfdbfe;font-weight:600;">🔒 Encrypted vault • Your data stays yours</span></div>
    </div>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([1.6, 1])

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
            ✅ <b>DigiLocker:</b> Coming soon<br>
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

        if st.button("G  Sign in with Google", use_container_width=True, key="google_standard"):
            if hasattr(st, "login"):
                st.login()
            else:
                st.error("Upgrade Streamlit to 1.42+ for Google login.")

        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;margin:14px 0;">
        <div style="flex:1;height:1px;background:#e2e8f0;"></div>
        <div style="font-size:0.7rem;color:#94a3b8;">OR</div>
        <div style="flex:1;height:1px;background:#e2e8f0;"></div>
        </div>
        <div style="padding:0 20px;">
        """, unsafe_allow_html=True)

        password_mode = st.radio(
            "Password account",
            ["Log in", "Create account"],
            horizontal=True,
            key="password_auth_mode",
            label_visibility="collapsed",
        )
        email_input = st.text_input("Email address", key="std_email")
        pass_input = st.text_input("Password", type="password", key="std_pass")

        if password_mode == "Create account":
            confirm_password = st.text_input(
                "Confirm password", type="password", key="std_pass_confirm"
            )
            st.caption(
                "Passwords are stored as salted hashes. Use at least 12 characters. "
                "Password recovery and email verification aren't available yet. "
                "Password accounts have a separate profile from Google accounts, even "
                "if they use the same email."
            )
            if st.button(
                "Create account", use_container_width=True, type="primary",
                key="std_register",
            ):
                if pass_input != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    try:
                        created, result = register_password_account(email_input, pass_input)
                    except sqlite3.Error:
                        print("Password account storage error: SQLite error")
                        st.error("Account service is temporarily unavailable. Please try again.")
                    else:
                        if created:
                            finish_login(
                                result, "Student", vault_identity=f"password:{result}"
                            )
                            st.rerun()
                        else:
                            st.error(result)
        elif st.button(
            "Log in", use_container_width=True, type="primary", key="std_login"
        ):
            if DEV_MODE and email_input:
                finish_login(email_input.strip().lower(), "Student")   # dev-only demo login
                st.rerun()
            else:
                try:
                    account_email = authenticate_password_account(email_input, pass_input)
                except sqlite3.Error:
                    print("Password account storage error: SQLite error")
                    st.error("Account service is temporarily unavailable. Please try again.")
                else:
                    if account_email:
                        finish_login(
                            account_email, "Student",
                            vault_identity=f"password:{account_email}",
                        )
                        st.rerun()
                    else:
                        st.error("Email or password is incorrect.")

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("""
        <div style="padding:10px 20px;border-top:1px solid #f1f5f9;margin-top:10px;">
        <div style="font-size:0.7rem;color:#64748b;text-align:center;">Other options:</div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("📱 Login with Mobile OTP", expanded=False):
            mobile = st.text_input("Mobile Number", placeholder="98XXXXXX10", max_chars=10, key="login_mob2")
            if st.button("Send OTP", use_container_width=True, type="secondary", key="send_otp2"):
                if valid_mobile(mobile):
                    ok, res = issue_otp(st.session_state, mobile)
                    if ok:
                        sent = False
                        try:
                            send_otp(mobile, res)
                            sent = True
                        except NotImplementedError:
                            st.error("SMS provider not configured yet.")
                        if sent:
                            st.session_state.otp_sent = True
                            st.rerun()
                    else:
                        st.error(res)
                else:
                    st.error("Enter valid mobile")
            if st.session_state.otp_sent:
                otp_in = st.text_input("Enter OTP", max_chars=6, key="otp_in2")
                if st.button("Verify & Login", use_container_width=True, type="primary", key="verify2"):
                    ok, m = check_otp(st.session_state, st.session_state.otp_mobile, otp_in)
                    if ok:
                        mob = st.session_state.otp_mobile
                        st.session_state.otp_sent = False
                        finish_login(f"{mob}@unisync.phone", f"User {mob[-4:]}")
                        st.session_state.vault_data["personal"].setdefault("mobile", mob)
                        st.rerun()
                    else:
                        st.error(m)

        if st.button("Guest Login (Skip)", use_container_width=True, key="guest2"):
            finish_login(f"guest-{secrets.token_hex(8)}@unisync.guest", "Guest")
            st.rerun()

        st.markdown("""
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# ---------------- HEADER ----------------
if not VAULT_READY:
    if "not configured" in VAULT_KEY_ERROR:
        st.warning(
            "Vault key is not configured. Add UNISYNC_MASTER_KEY to "
            ".streamlit/secrets.toml or your deployment's Streamlit secrets. "
            "Data will not be saved between sessions."
        )
    else:
        st.error(f"Vault key configuration error: {VAULT_KEY_ERROR}")

col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("""
    <div style="background:white;border:1px solid #e2e8f0;border-top:5px solid #1e40af;padding:14px 18px;border-radius:10px;">
    <h1 style="margin:0;color:#0f172a;font-size:1.5rem;">🎓 UniSync</h1>
    <p style="margin:4px 0 0 0;color:#1e40af;font-size:0.9rem;font-weight:700;">One Stop Solution for Filling All Entrance Exam / Job Exam and All Counselling</p>
    </div>
    """, unsafe_allow_html=True)
with col_h2:
    p = st.session_state.vault_data.get("personal", {})
    docs = st.session_state.vault_data.get("docs", {})
    has_docs_count = len(docs)
    st.markdown(f"""
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px;">
    <div style="font-size:0.8rem;font-weight:600;color:#0f172a;">👤 {esc(st.session_state.user_name)}</div>
    <div style="font-size:0.65rem;color:#64748b;word-break:break-all;">{esc(st.session_state.user_email)}</div>
    <div style="font-size:0.65rem;color:#22c55e;margin-top:4px;">✅ Signed in</div>
    <div style="font-size:0.65rem;color:#475569;">🔗 DigiLocker: {'✅ Linked' if st.session_state.gov_linked else 'Coming soon'}</div>
    <div style="font-size:0.65rem;color:#475569;">📄 Docs: {has_docs_count} uploaded</div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Logout", key="logout", use_container_width=True, type="secondary"):
        _was_google = bool(getattr(getattr(st, "user", None), "is_logged_in", False))
        st.session_state.clear()
        if _was_google and hasattr(st, "logout"):
            st.logout()
        else:
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

# ---------------- SIDEBAR: SCHOLARSHIPS + PRIVACY ----------------
with st.sidebar:
    st.markdown("""
    <div style="background:#0f172a;color:white;padding:12px;border-radius:10px;margin-bottom:12px;">
    <div style="font-size:0.95rem;font-weight:800;">💰 Scholarship Details - UG & PG</div>
    <div style="font-size:0.65rem;color:#94a3b8;margin-top:3px;">Click Apply - With dates & links</div>
    </div>
    """, unsafe_allow_html=True)

    sch_search = st.text_input("🔍 Search scholarship", placeholder="Search NSP, Vidya Lakshmi, Rajasthan, US, Fulbright...", key="sch_search_final", label_visibility="collapsed")

    tab_ug, tab_pg = st.tabs(["🎓 UG", "🎓 PG"])

    def render_sch_card(sch):
        if sch_search and sch_search.lower() not in (sch["name"] + sch["desc"] + sch["type"]).lower():
            return False
        st.markdown(f"""
        <div style="background:white;border:1px solid #e2e8f0;border-left:4px solid #1e40af;border-radius:8px;padding:10px 10px 4px 10px;margin-bottom:0px;">
        <div style="font-size:0.8rem;font-weight:700;color:#0f172a;line-height:1.2;">{sch['name']}</div>
        <div style="font-size:0.65rem;color:#22c55e;font-weight:600;margin:3px 0;">💰 {sch['amount']}</div>
        <div style="font-size:0.6rem;color:#1e40af;font-weight:600;">📅 {sch['deadline']} | {sch['type']}</div>
        <div style="font-size:0.62rem;color:#475569;margin:4px 0 0 0;line-height:1.3;">{sch['desc']}</div>
        </div>
        """, unsafe_allow_html=True)
        st.link_button(f"🔗 Apply - {sch['name'][:22]}", sch['link'], use_container_width=True, type="secondary")
        st.caption(f"{sch['link']}")
        st.markdown("<div style='margin-bottom:10px;'></div>", unsafe_allow_html=True)
        return True

    with tab_ug:
        st.caption(f"{len(SCHOLARSHIP_UG)} UG scholarships - PM Vidya Lakshmi, Rajasthan Abroad, US, etc")
        for sch in SCHOLARSHIP_UG:
            render_sch_card(sch)

    with tab_pg:
        st.caption(f"{len(SCHOLARSHIP_PG)} PG scholarships - GATE, Fulbright US, Chevening UK, DAAD, etc")
        for sch in SCHOLARSHIP_PG:
            render_sch_card(sch)

    st.markdown("---")
    st.link_button("🔗 NSP Portal", "https://scholarships.gov.in", use_container_width=True)
    st.link_button("🔗 PM Vidya Lakshmi", "https://www.vidyalakshmi.co.in", use_container_width=True)
    st.link_button("🔗 Rajasthan SJE", "https://sje.rajasthan.gov.in", use_container_width=True)
    st.link_button("🔗 USIEF Fulbright US", "https://www.usief.org.in", use_container_width=True)

    # --- Privacy (DPDP Act 2023) ---
    st.markdown("---")
    st.markdown("**🔒 Your data & privacy**")
    st.checkbox("I consent to UniSync storing my data (encrypted) so I can autofill forms", key="consent")
    st.download_button("📥 Download my data",
                       data=json.dumps((export_user_data(st.session_state.get("vault_identity") or st.session_state.user_email) if VAULT_READY else None) or st.session_state.vault_data, indent=2, ensure_ascii=False),
                       file_name="my-unisync-data.json", mime="application/json", use_container_width=True, key="dl_my_data")
    if st.button("🗑 Delete all my data", use_container_width=True, key="del_my_data"):
        if VAULT_READY:
            delete_user_data(st.session_state.get("vault_identity") or st.session_state.user_email)
        st.session_state.clear()
        st.rerun()


# ---------------- PROGRESS ----------------
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

# ---------------- DEADLINES (sample data - labelled honestly) ----------------
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
<div style="font-size:0.65rem;color:#64748b;">Sample dates - always confirm on the official site</div>
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
    | Exam | Last Date | Status | Official Source | Note |
    |------|-----------|--------|-----------------|------|
    | JEE Main 2026 | 22 Nov 2025 | 🔴 Closing Soon | [jeemain.nta.nic.in](https://jeemain.nta.nic.in) | Sample date |
    | NEET UG 2026 | 15 Dec 2025 | 🔵 Opens Soon | [neet.nta.nic.in](https://neet.nta.nic.in) | Sample date |
    | CUET UG 2026 | 30 Mar 2026 | 🟢 Open Now | [cuet.nta.nic.in](https://cuet.nta.nic.in) | Sample date |
    | BITSAT 2026 | 15 Dec 2025 | 🔵 Opens Soon | [bitsadmission.com](https://www.bitsadmission.com) | Sample date |
    | JoSAA 2026 | 10 June 2026 | 🟡 Upcoming | [josaa.nic.in](https://josaa.nic.in) | Sample date |
    | MCC NEET UG | 20 June 2026 | 🟡 Upcoming | [mcc.nic.in](https://mcc.nic.in) | Sample date |
    | REAP Rajasthan | 15 June 2026 | 🟡 Upcoming | [reap2025.com](https://reap2025.com) | Govt & Pvt Colleges RTU, JECRC |
    | KCET Karnataka | 10 Apr 2026 | 🔵 Opens Soon | [cetonline.karnataka.gov.in](https://cetonline.karnataka.gov.in) | Govt & Pvt Colleges |
    | CLAT 2026 | 20 Dec 2025 | 🔵 Opens Soon | [consortiumofnlus.ac.in](https://consortiumofnlus.ac.in) | 24 NLUs |
    | CAT 2025 | 23 Nov 2025 | 🔴 Closing Soon | [iimcat.ac.in](https://iimcat.ac.in) | IIMs |
    | UPSC CSE 2026 | 21 Feb 2026 | 🟡 Upcoming | [upsc.gov.in](https://upsc.gov.in) | Civil Services |
    | SSC CGL 2026 | 15 Jan 2026 | 🟡 Upcoming | [ssc.nic.in](https://ssc.nic.in) | Staff Selection |
    | RRB Railway | 30 Nov 2025 | 🔴 Closing Soon | [rrbcdg.gov.in](https://rrbcdg.gov.in) | Railway Jobs |
    | IBPS PO | 10 Dec 2025 | 🔵 Opens Soon | [ibps.in](https://ibps.in) | Banking |
    """)
    st.caption("These are sample dates and are NOT live. Always click the source link and confirm the last date on the official site before applying.")
    if st.button("🔄 Sync Now - Fetch Latest from Official Sites", key="sync_deadlines"):
        st.info("Live sync is not connected yet. Dates above are samples - please verify on the official sites.")

# ---------------- STEP 1 ----------------
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
    if st.button("Select Exam Application", key="s_exam", use_container_width=True, type="primary" if st.session_state.application_type == "EXAM" else "secondary"):
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
    if st.button("Select Counseling", key="s_couns", use_container_width=True, type="primary" if st.session_state.application_type == "COUNSELING" else "secondary"):
        st.session_state.application_type = "COUNSELING"
        st.rerun()

# ---------------- STEP 2 ----------------
st.markdown('---')
st.markdown(f"## Step 2: Select {'Entrance Exams' if st.session_state.application_type == 'EXAM' else 'Counseling Programs'}")

EXAM_LIST = {
    "Engineering Entrance": ["JEE Main", "BITSAT", "VITEEE", "SRMJEEE", "MET Manipal", "COMEDK"],
    "Medical Entrance": ["NEET UG - MBBS, BDS", "NEET PG - MD, MS", "AIIMS INI-CET", "AIIMS Nursing"],
    "Central Universities (CUET)": ["CUET UG - DU, BHU, JNU, AMU", "CUET PG", "NCET"],
    "Law, Design & Fashion": ["CLAT - 24 NLUs", "AILET", "NID - Design", "NIFT - Fashion", "NATA - Architecture"],
    "Management & Government Jobs": ["CAT - IIMs", "XAT - XLRI", "MAT - MBA", "CMAT", "GATE - PSU", "UPSC", "SSC CGL", "RRB Railway", "NDA, CDS, Agniveer", "IBPS Banking"],
    "Private Universities - Direct Admission": ["LNMIIT Jaipur", "Thapar Patiala", "Nirma Ahmedabad", "Jaypee Noida", "Amity University", "LPU", "Bennett University", "Shiv Nadar", "UPES Dehradun"],
}
COUNSELING_LIST = {
    "Medical Counseling": ["MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)", "MCC NEET PG - MD, MS", "State Medical Counseling - Rajasthan, UP, MP", "AACCC AYUSH - BAMS, BHMS", "AIIMS INI-CET Counseling"],
    "IIT, NIT, IIIT Counseling": ["JoSAA - IIT, NIT, IIIT, GFTI", "CSAB Special Round", "JAC Delhi - DTU, NSUT, IIIT Delhi", "JAC Chandigarh - PEC, UIET"],
    "State Engineering Counseling": ["REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya", "WBJEE - Jadavpur University - State Colleges", "MHT-CET CAP - Govt Colleges Maharashtra - COEP, VJTI", "KCET - Karnataka - Govt & Pvt Colleges", "COMEDK Karnataka", "UPTAC - AKTU UP", "MP DTE", "Haryana HSTES", "Gujarat ACPC"],
    "Private University Counseling": ["LNMIIT Jaipur Counseling", "Thapar Patiala Counseling", "VIT Vellore Counseling", "SRM Chennai Counseling", "Manipal University Counseling", "Nirma University Counseling", "Jaypee Noida Counseling", "Bennett University Counseling"],
}
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
cur = EXAM_LIST if st.session_state.application_type == "EXAM" else COUNSELING_LIST
if not st.session_state.application_type:
    cur = EXAM_LIST

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
for rs in range(0, len(cats), 4):
    row = cats[rs:rs + 4]
    cols = st.columns(4)
    for ci, (cat, exams) in enumerate(row):
        with cols[ci]:
            st.markdown(f"""<div class="compact-cat"><h4>{cat}</h4><div style="font-size:0.6rem;color:#64748b;">{len(exams)} exams</div></div>""", unsafe_allow_html=True)
            for ex in exams:
                sel = ex in st.session_state.selected_endpoints
                dot = "🟢" if sel else "⚪"
                date_str = EXAM_DATES.get(ex, "")
                if "Closing" in date_str:
                    badge_bg = "#fef2f2"; badge_color = "#dc2626"; border = "#fecaca"
                elif "Open till" in date_str or "Open" in date_str:
                    badge_bg = "#f0fdf4"; badge_color = "#15803d"; border = "#bbf7d0"
                elif "June" in date_str or "July" in date_str or "Upcoming" in date_str:
                    badge_bg = "#fffbeb"; badge_color = "#d97706"; border = "#fde68a"
                else:
                    badge_bg = "#eff6ff"; badge_color = "#1e40af"; border = "#bfdbfe"

                c_chk, c_date = st.columns([3.2, 1.8])
                with c_chk:
                    already_one_selected = len(st.session_state.selected_endpoints) >= 1 and ex not in st.session_state.selected_endpoints
                    if already_one_selected:
                        st.checkbox(f"{dot} {ex} ⛔ Only 1 allowed - Deselect {st.session_state.selected_endpoints[0]} first", value=False, key=f"chk_{cat}_{ex}_{rs}_{ci}_{date_str[:2]}", disabled=True)
                        checked = False
                    else:
                        checked = st.checkbox(f"{dot} {ex}", value=sel, key=f"chk_{cat}_{ex}_{rs}_{ci}_{date_str[:2]}")
                with c_date:
                    if date_str:
                        st.markdown(f"""<div style="background:{badge_bg};color:{badge_color};border:1px solid {border};font-size:0.6rem;font-weight:600;padding:2px 6px;border-radius:10px;text-align:center;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{date_str}</div>""", unsafe_allow_html=True)

                if checked and ex not in st.session_state.selected_endpoints:
                    st.session_state.selected_endpoints = [ex]
                    persist()
                    st.rerun()
                elif not checked and ex in st.session_state.selected_endpoints:
                    st.session_state.selected_endpoints.remove(ex)
                    persist()
                    st.rerun()
if st.session_state.selected_endpoints:
    st.success(f"✅ {len(st.session_state.selected_endpoints)} selected" + (" - Saved (encrypted) for next login" if st.session_state.get("consent") and VAULT_READY else " - Tick the consent box in the sidebar to save for next login"))

# ---------------- STEP 3 ----------------
st.markdown('---')
st.markdown('## Step 3: Checklist / Documents')


def store_file(key, data):
    """Encrypted file storage - only with consent and a configured vault key."""
    if st.session_state.get("consent") and VAULT_READY:
        save_file(st.session_state.get("vault_identity") or st.session_state.user_email, key, data)


col_digi, _ = st.columns([1, 2])
with col_digi:
    if not st.session_state.gov_linked:
        st.button("🔗 Link DigiLocker (coming soon)", use_container_width=True, disabled=True,
                  help="Needs DigiLocker partner access. Until then, upload your documents below.")
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
    st.warning(f"Pending: {', '.join(pending)} - Upload below")
else:
    st.success("✅ All documents ready")

st.markdown("""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:6px 10px;margin-bottom:8px;font-size:0.7rem;"><b>Format Guide (System Works):</b> Photo: JPG/PNG 10-200KB White BG | Sign: JPG/PNG 4-30KB | Marksheets: PDF/JPG/PNG Max 2MB | Scorecard: PDF/JPG/PNG Max 2MB | Accepted: JPG, JPEG, PNG, PDF</div>""", unsafe_allow_html=True)

SIGN_PRESET = "Signature (350×140, 4-30KB)"
if is_counseling or not st.session_state.application_type:
    items = [("👤 Passport Photo", has_photo, "photo", "JPG/PNG 10-200KB White BG"), ("✍ Signature", has_sign, "sign", "JPG/PNG 4-30KB"), ("🎓 Class 10th", has_10th, "10th", "PDF/JPG/PNG Max 2MB"), ("📝 Class 12th", has_12th, "12th", "PDF/JPG/PNG Max 2MB"), ("📊 Score/Rank", has_score, "score_entry", "AIR/Rank"), ("📄 Scorecard PDF/JPG", has_scorecard, "scorecard", "PDF/JPG/PNG Max 2MB")]
else:
    items = [("👤 Passport Photo", has_photo, "photo", "JPG/PNG 10-200KB White BG"), ("✍ Signature", has_sign, "sign", "JPG/PNG 4-30KB"), ("🎓 Class 10th", has_10th, "10th", "PDF/JPG/PNG Max 2MB"), ("📝 Class 12th", has_12th, "12th", "PDF/JPG/PNG Max 2MB")]

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
                    persist()
                    st.rerun()
            else:
                is_photo = "Photo" in name
                is_sign = "Sign" in name

                if is_photo or is_sign:
                    if is_photo:
                        target_w, target_h, min_kb, max_kb = 413, 531, 10, 200
                        preset_name = "Passport Photo (413×531, 10-200KB)"
                    else:
                        target_w, target_h, min_kb, max_kb = 350, 140, 4, 30
                        preset_name = SIGN_PRESET

                    f = st.file_uploader(f"Upload {name} - {preset_name} - Any JPG/PNG/WebP (Phone photo OK)", key=f"up_{idx}_{key}", type=["jpg", "jpeg", "png", "webp"], label_visibility="collapsed")

                    if f:
                        data = f.getvalue()
                        kind, why = validate_upload(data, allow=("jpg", "png", "webp"))
                        if not kind:
                            st.error(why)
                        else:
                            with st.spinner(f"Auto-fixing {name} to {preset_name}..."):
                                processed_data, msg, size = process_portal_image(data, target_w, target_h, min_kb, max_kb, is_signature=is_sign)
                            if processed_data:
                                store_file(key, processed_data)
                                st.session_state.vault_data["docs"][name] = f"{name} - {msg}"
                                if is_photo:
                                    st.session_state.vault_data["personal"]["photo_uploaded"] = True
                                else:
                                    st.session_state.vault_data["personal"]["sign_uploaded"] = True
                                st.image(processed_data, caption=f"✅ {msg}", width=150)
                                st.success(f"✅ {name} auto-fixed: {msg} - Portal will accept!")
                                st.download_button(f"📥 Download Portal-Ready {name}", data=processed_data, file_name=f"portal_{key}.jpg", mime="image/jpeg", key=f"dl_{idx}_{key}")
                                persist()
                            else:
                                st.error(msg)
                else:
                    f = st.file_uploader(f"Upload {name}", key=f"up_{idx}_{key}", type=["jpg", "jpeg", "png", "pdf"], label_visibility="collapsed")
                    if f:
                        data = f.getvalue()
                        kind, why = validate_upload(data, allow=("jpg", "png", "pdf"))
                        if not kind:
                            st.error(why)
                        else:
                            pdata = st.session_state.vault_data["personal"]
                            if "10th" in name or "12th" in name:
                                is_10th_marksheet = "10th" in name
                                try:
                                    text, how = extract_text(data, kind)
                                except RuntimeError as exc:
                                    st.error(f"Document extraction could not run: {exc}")
                                    text, how = "", "unavailable"
                                ext = parse_marksheet(text)
                                if "OCR fallback unavailable" in how:
                                    st.warning(f"Could not run OCR, so only selectable PDF text was checked. {how}")
                                if "percentage" in ext and ext["percentage"][1] == 0.5:
                                    st.caption("Estimated from the best five subject totals. Verify that the admission authority uses this best-five policy.")
                                review_fields = [
                                    ("Student name", "name"),
                                    ("Father's name", "fatherName"),
                                    ("Roll number", "roll_no"),
                                    ("Percentage", "percentage"),
                                ]
                                if is_10th_marksheet:
                                    review_fields.insert(2, ("DOB", "dob"))
                                extracted_details = [
                                    f"{label}: {ext[field][0]}"
                                    for label, field in review_fields
                                    if field in ext and ext[field][0]
                                ]
                                extracted_field_labels = [
                                    label
                                    for label, field in review_fields
                                    if field in ext and ext[field][0]
                                ]
                                if extracted_details:
                                    with st.expander("Review relevant details from the marksheet"):
                                        detail_columns = st.columns(2)
                                        for detail_index, detail in enumerate(extracted_details):
                                            with detail_columns[detail_index % 2]:
                                                label, value = detail.split(": ", 1)
                                                st.markdown(f"**{label}**")
                                                st.write(value)
                                signature_dates = set(filter(None, ext.get("_signature_dates", ("", 0))[0].split(",")))
                                saved_dob = str(pdata.get("dob") or "")
                                saved_dob_match = re.fullmatch(r"(\d{1,2})[-/.](\d{1,2})[-/.]((?:19|20)\d{2})", saved_dob)
                                saved_iso_dob_match = re.fullmatch(r"((?:19|20)\d{2})[-/.](\d{1,2})[-/.](\d{1,2})", saved_dob)
                                normalized_saved_dob = (
                                    f"{int(saved_dob_match.group(1)):02d}-{int(saved_dob_match.group(2)):02d}-{saved_dob_match.group(3)}"
                                    if saved_dob_match else (
                                        f"{int(saved_iso_dob_match.group(3)):02d}-{int(saved_iso_dob_match.group(2)):02d}-{saved_iso_dob_match.group(1)}"
                                        if saved_iso_dob_match else saved_dob
                                    )
                                )
                                stale_signature_dob = normalized_saved_dob in signature_dates
                                has_extracted_fields = bool(extracted_field_labels)
                                form_id = hashlib.sha256(data).hexdigest()[:12]
                                with st.form(f"confirm_{idx}_{key}_{form_id}"):
                                    st.caption(
                                        f"Read via {how}: extracted {', '.join(extracted_field_labels)}. "
                                        "Verify the values; blank fields were not found in the marksheet."
                                        if has_extracted_fields else
                                        (
                                            "No reliable form fields were found. Check the original document and enter details below; digital-signature dates are not treated as DOB."
                                            if is_10th_marksheet else
                                            "No reliable form fields were found. Check the original document and enter details below."
                                        )
                                    )

                                    def _fv(k):
                                        return ext.get(k, ("", 0))[0]

                                    def _lc(k):
                                        return k in ext and ext[k][1] < 0.8

                                    extracted_father = str(_fv("fatherName") or "").strip().casefold()
                                    saved_name_is_father = bool(
                                        extracted_father
                                        and str(pdata.get("name") or "").strip().casefold() == extracted_father
                                    )
                                    extracted_name_is_father = bool(
                                        extracted_father
                                        and str(_fv("name") or "").strip().casefold() == extracted_father
                                    )
                                    name_default = (
                                        "" if saved_name_is_father or extracted_name_is_father
                                        else _fv("name") or pdata.get("name", "")
                                    )
                                    student_col, father_col = st.columns(2)
                                    with student_col:
                                        nm = st.text_input(
                                            "Student name" + (" ⚠ verify" if _lc("name") else ""),
                                            value=name_default,
                                            key=f"marksheet_{form_id}_name",
                                        )
                                    with father_col:
                                        fn = st.text_input(
                                            "Father's name" + (" ⚠ verify" if _lc("fatherName") else ""),
                                            value=_fv("fatherName") or pdata.get("fatherName", ""),
                                            key=f"marksheet_{form_id}_father_name",
                                        )
                                    st.caption("If the marksheet has no percentage, the best-five estimate is used when five subject totals are detected; otherwise, enter it manually and verify the board's policy.")
                                    roll_col, secondary_col = st.columns(2)
                                    with roll_col:
                                        roll_no = st.text_input(
                                            "Roll number" + (" ⚠ verify" if _lc("roll_no") else ""),
                                            value=_fv("roll_no") or pdata.get("roll_no", ""),
                                            key=f"marksheet_{form_id}_roll_no",
                                        )
                                    if is_10th_marksheet:
                                        dob_default = _fv("dob") or ("" if stale_signature_dob else saved_dob)
                                        with secondary_col:
                                            dob = st.text_input(
                                                "DOB (DD-MM-YYYY)" + (" ⚠ verify" if _lc("dob") else ""),
                                                value=dob_default,
                                                key=f"marksheet_{form_id}_dob",
                                            )
                                        percentage_col = st.container()
                                    else:
                                        percentage_col = secondary_col
                                    with percentage_col:
                                        pct = st.text_input(
                                            "Percentage" + (" ⚠ verify" if _lc("percentage") else ""),
                                            value=_fv("percentage"),
                                            key=f"marksheet_{form_id}_percentage",
                                        )
                                    if st.form_submit_button("Confirm & Save"):
                                        try:
                                            ok_pct = 0 < float(pct) <= 100
                                        except ValueError:
                                            ok_pct = False
                                        if not ok_pct:
                                            st.error("Enter a valid percentage (0-100)")
                                        else:
                                            pdata["class10_percentage" if "10th" in name else "class12_percentage"] = pct
                                            if nm: pdata["name"] = nm
                                            elif saved_name_is_father or extracted_name_is_father:
                                                pdata.pop("name", None)
                                            if fn: pdata["fatherName"] = fn
                                            if roll_no: pdata["roll_no"] = roll_no
                                            if is_10th_marksheet:
                                                if dob: pdata["dob"] = dob
                                                elif stale_signature_dob:
                                                    pdata.pop("dob", None)
                                            st.session_state.vault_data["docs"][name] = f.name
                                            store_file(key, data)
                                            persist()
                                            st.rerun()
                            elif "Category" in name:
                                with st.form(f"confirm_{idx}_{key}"):
                                    cat_val = st.selectbox("Category (as on certificate)", ["OBC-NCL", "SC", "ST", "EWS", "General"])
                                    if st.form_submit_button("Confirm & Save"):
                                        pdata["category"] = cat_val
                                        st.session_state.vault_data["docs"][name] = f.name
                                        store_file(key, data)
                                        persist()
                                        st.rerun()
                            else:
                                st.session_state.vault_data["docs"][name] = f.name
                                store_file(key, data)
                                st.success(f"✅ {name} uploaded")
                                persist()
                                st.rerun()
        else:
            st.markdown(f"""<div style="border:1px solid #86efac;background:#f0fdf4;border-radius:6px;padding:6px;margin-bottom:4px;min-height:50px;"><b style="color:#15803d;font-size:0.75rem;">✅ {name}</b><br><span style="font-size:0.6rem;color:#166534;">{esc(docs.get(name, 'Ready'))} | {fmt}</span></div>""", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Change", key=f"chg_{idx}_{key}", use_container_width=True):
                    if name in st.session_state.vault_data["docs"]:
                        del st.session_state.vault_data["docs"][name]
                    if "Photo" in name:
                        st.session_state.vault_data["personal"]["photo_uploaded"] = False
                    if "Sign" in name:
                        st.session_state.vault_data["personal"]["sign_uploaded"] = False
                    persist()
                    st.rerun()
            with c2:
                if st.button("Remove", key=f"rem_{idx}_{key}", use_container_width=True):
                    if name in st.session_state.vault_data["docs"]:
                        del st.session_state.vault_data["docs"][name]
                    if "Photo" in name:
                        st.session_state.vault_data["personal"]["photo_uploaded"] = False
                    if "Sign" in name:
                        st.session_state.vault_data["personal"]["sign_uploaded"] = False
                    if "10th" in name:
                        st.session_state.vault_data["personal"].pop("class10_percentage", None)
                    if "12th" in name:
                        st.session_state.vault_data["personal"].pop("class12_percentage", None)
                    if key == "score_entry":
                        st.session_state.vault_data["scores"] = {}
                    if VAULT_READY:
                        delete_file(st.session_state.get("vault_identity") or st.session_state.user_email, key)
                    persist()
                    st.rerun()

# ---------------- STEP 4 ----------------
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
    personal = dict(st.session_state.vault_data.get("personal", {}))
    docs = st.session_state.vault_data.get("docs", {})
    scores = st.session_state.vault_data.get("scores", {})
    if not personal and not docs and not scores:
        return None
    em = st.session_state.user_email
    if em and not em.endswith(("@unisync.phone", "@unisync.guest")):
        personal.setdefault("email", em)
    has_photo = any("Photo" in k for k in docs) or personal.get("photo_uploaded", False)
    has_sign = any("Sign" in k for k in docs) or personal.get("sign_uploaded", False)
    has_10th = any("10th" in k for k in docs) or bool(personal.get("class10_percentage"))
    has_12th = any("12th" in k for k in docs) or bool(personal.get("class12_percentage"))
    has_cat = any("Category" in k for k in docs) or personal.get("category") not in ["", None, "General"]
    has_score = len(scores) > 0
    has_scorecard = any("Scorecard" in k for k in docs)
    return {
        "personal": personal,
        "docs_status": {"photo": has_photo, "sign": has_sign, "tenth": has_10th, "twelfth": has_12th, "cat": has_cat, "score": has_score, "scorecard": has_scorecard, "score_val": list(scores.values())[0] if scores else "", "scorecard_name": docs.get("📄 Scorecard PDF/JPG", "")},
        "json": autofill_json(personal, scores),
    }


st.markdown("### Your Data Preview - AutoFill Ready")

data = get_autofill()
if data is None:
    st.info("Upload docs in Step 3 - Preview will show here")
    json_str = '{"personal": {"fullName": "", "fatherName": "", "mobile": "", "category": ""}}'
    docs_status = {"photo": False, "sign": False, "tenth": False, "twelfth": False, "cat": False, "score": False, "scorecard": False, "score_val": "", "scorecard_name": ""}
    pers = {}
    ds = docs_status
else:
    pers = data["personal"]
    ds = data["docs_status"]
    st.success(f"✅ Ready: {pers.get('name', 'Student')} | {pers.get('category', '')} | Score: {ds['score_val'] if ds['score'] else 'N/A'}")
    st.markdown(f"""<div style="background:#f0fdf4;border:1px solid #22c55e;border-radius:6px;padding:6px 10px;margin:6px 0;font-size:0.75rem;"><b>Docs:</b> 📸 Photo: {'✅' if ds['photo'] else '❌'} | ✍ Sign: {'✅' if ds['sign'] else '❌'} | 🎓 10th: {'✅' if ds['tenth'] else '❌'} | 📝 12th: {'✅' if ds['twelfth'] else '❌'} | 📊 Score: {'✅ ' + esc(ds['score_val']) if ds['score'] else '❌'} | 📄 Scorecard: {'✅' if ds['scorecard'] else '❌'}</div>""", unsafe_allow_html=True)
    preview_identity = st.session_state.get("vault_identity") or st.session_state.user_email
    preview_user_key = hashlib.sha256(preview_identity.encode()).hexdigest()[:10]

    def preview_widget_key(field, value):
        value_key = hashlib.sha256(str(value or "").encode()).hexdigest()[:10]
        return f"step4_{preview_user_key}_{field}_{value_key}"

    st.markdown("#### Review and edit your application details")
    st.caption("These are the values included in the AutoFill preview. Correct them here before copying the data or opening an application.")
    score_keys = list(st.session_state.vault_data.get("scores", {}))
    score_key = score_keys[0] if score_keys else "Rank"
    score_value = st.session_state.vault_data.get("scores", {}).get(score_key, "")
    with st.form("step4_data_review"):
        col1, col2 = st.columns(2)
        with col1:
            preview_name = st.text_input(
                "Student name", value=str(pers.get("name") or ""),
                key=preview_widget_key("name", pers.get("name")),
            )
            preview_father = st.text_input(
                "Father's name", value=str(pers.get("fatherName") or ""),
                key=preview_widget_key("father", pers.get("fatherName")),
            )
            preview_mother = st.text_input(
                "Mother's name", value=str(pers.get("motherName") or ""),
                key=preview_widget_key("mother", pers.get("motherName")),
            )
            preview_dob = st.text_input(
                "Date of birth (DD-MM-YYYY)", value=str(pers.get("dob") or ""),
                key=preview_widget_key("dob", pers.get("dob")),
            )
            preview_roll_no = st.text_input(
                "Roll number", value=str(pers.get("roll_no") or ""),
                key=preview_widget_key("roll_no", pers.get("roll_no")),
            )
        with col2:
            preview_mobile = st.text_input(
                "Mobile number", value=str(pers.get("mobile") or ""),
                key=preview_widget_key("mobile", pers.get("mobile")),
            )
            preview_email = st.text_input(
                "Email address", value=str(pers.get("email") or ""),
                key=preview_widget_key("email", pers.get("email")),
            )
            preview_category = st.text_input(
                "Category", value=str(pers.get("category") or ""),
                key=preview_widget_key("category", pers.get("category")),
            )
            preview_class10 = st.text_input(
                "Class 10 percentage", value=str(pers.get("class10_percentage") or ""),
                key=preview_widget_key("class10_percentage", pers.get("class10_percentage")),
            )
            preview_class12 = st.text_input(
                "Class 12 percentage", value=str(pers.get("class12_percentage") or ""),
                key=preview_widget_key("class12_percentage", pers.get("class12_percentage")),
            )
            preview_score = st.text_input(
                "Exam rank / score", value=str(score_value or ""),
                key=preview_widget_key("score", score_value),
            )
        if st.form_submit_button("Save reviewed details", type="primary"):
            invalid_percentages = []
            for label, value in (
                ("Class 10 percentage", preview_class10),
                ("Class 12 percentage", preview_class12),
            ):
                if value.strip():
                    try:
                        percentage = float(value.strip().rstrip("%"))
                    except ValueError:
                        invalid_percentages.append(f"{label} must be a number from 0 to 100.")
                    else:
                        if not 0 <= percentage <= 100:
                            invalid_percentages.append(f"{label} must be from 0 to 100.")
            if invalid_percentages:
                for message in invalid_percentages:
                    st.error(message)
            else:
                reviewed_fields = {
                    "name": preview_name,
                    "fatherName": preview_father,
                    "motherName": preview_mother,
                    "dob": preview_dob,
                    "roll_no": preview_roll_no,
                    "mobile": preview_mobile,
                    "email": preview_email,
                    "category": preview_category,
                    "class10_percentage": preview_class10,
                    "class12_percentage": preview_class12,
                }
                for field, value in reviewed_fields.items():
                    st.session_state.vault_data["personal"][field] = value.strip()
                if preview_score.strip():
                    st.session_state.vault_data["scores"][score_key] = preview_score.strip()
                elif score_key in st.session_state.vault_data["scores"]:
                    del st.session_state.vault_data["scores"][score_key]
                persist()
                st.success("Reviewed details updated. The AutoFill preview below now uses these values.")
                st.rerun()

    data = get_autofill()
    pers = data["personal"] if data else {}
    ds = data["docs_status"] if data else docs_status
    json_str = json.dumps(data["json"] if data else {}, indent=2, ensure_ascii=False)
    docs_status = ds

# ---------------- AUTOFILL ----------------
st.markdown("#### AutoFill - Choose Option")

AUTOFILL_OPTIONS = {
    "Chrome Extension": "📦 Chrome Extension (Click to fill) - Download & Install",
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

    if opt_key in st.session_state.selected_autofill:
        st.download_button("📦 Download Extension", data=create_extension_zip(), file_name="unisync-extension.zip", mime="application/zip", use_container_width=True, type="primary", key=f"ext_{opt_key}")
        st.caption("chrome://extensions → Developer Mode ON → Load Unpacked (unzip first). The extension fills only when you click 'Fill Now', and only on supported exam sites.")

if st.session_state.selected_autofill:
    st.success(f"✅ {len(st.session_state.selected_autofill)} AutoFill method selected")
    with st.expander("📋 View JSON - Copy this for Extension", expanded=True):
        st.markdown("**📋 Step 1: Click Copy icon (top-right corner of code box) to copy your Step 3 data**")
        st.code(json_str, language="json")
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("📥 Download JSON File", data=json_str.encode(), file_name="unisync-my-data.json", mime="application/json", use_container_width=True)
        with c2:
            st.markdown("**Step 2: Paste in Extension Popup**")
            st.caption("Open Puzzle Icon → UniSync → Paste → Save Data")
        st.info("**How to use:** 1. Copy the JSON above 2. Open the extension, paste and Save Data 3. Open the exam site 4. Click Fill Now and review every field before submitting")
else:
    st.info("👆 Click dot above to select AutoFill method - Then your Step 3 data will auto-fill")

st.markdown("---")
if st.session_state.selected_endpoints:
    st.markdown(f"#### 🎯 Apply Now - {esc(st.session_state.selected_endpoints[0])} - Click to Apply")
else:
    st.markdown("#### 🎯 Apply Now - Select 1 exam in Step 2 first - Then Apply Button Will Appear")

if not st.session_state.selected_endpoints:
    st.info("Select exams in Step 2 to filter - Showing all popular exams below")
    display_endpoints = ["JEE Main", "BITSAT", "NEET UG - MBBS, BDS", "CUET UG - DU, BHU, JNU, AMU", "JoSAA - IIT, NIT, IIIT, GFTI", "LNMIIT Jaipur", "REAP Rajasthan - Govt & Pvt Colleges Rajasthan - RTU, JECRC, SKIT, Poornima, Arya", "MCC NEET UG - MBBS, BDS (AIIMS, JIPMER)"]
else:
    display_endpoints = st.session_state.selected_endpoints

cols = st.columns(2)
for idx, ep in enumerate(display_endpoints):
    url = get_url(ep)
    direct_url = get_direct(ep)
    with cols[idx % 2]:
        st.markdown(f"""<div style="border:1px solid #e2e8f0;border-radius:6px;padding:8px;margin-bottom:4px;background:white;"><b style="font-size:0.8rem;">{esc(ep)}</b><br><span style="font-size:0.6rem;color:#64748b;">{esc(url)}</span><br><span style="font-size:0.6rem;color:#22c55e;">✅ Official link</span></div>""", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.link_button("📝 Apply Now", direct_url, type="primary", use_container_width=True, key=f"ap_{ep}_{idx}")
        with c2:
            st.link_button("🏠 Info", url, use_container_width=True, key=f"in_{ep}_{idx}")

# ---------------- STEP 5 ----------------
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
            st.session_state.choices.append({"college": new_college, "branch": new_branch, "priority": len(st.session_state.choices) + 1})
            st.success(f"Added: {new_college} - {new_branch}")
            st.rerun()

    if st.session_state.choices:
        st.markdown("#### 📋 Your Choice Filling Order (Priority 1 is highest)")
        for idx, ch in enumerate(st.session_state.choices):
            c1, c2, c3 = st.columns([1, 3, 1])
            with c1:
                st.markdown(f"**#{idx + 1}**")
            with c2:
                st.text(f"{ch['college']} - {ch['branch']}")
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

# ---------------- STEP 6 ----------------
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
        <b>{esc(al['round'])}</b> - {esc(al['college'])}<br>
        Status: <span style="color:{status_color};font-weight:700;">{esc(al['status'])}</span> | Reporting by: {esc(al['date'])}
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
            st.caption("This is a rough guide only. Always check the official opening/closing ranks.")
        except ValueError:
            st.error("Enter valid rank number")
    else:
        st.info("Enter rank to predict - then confirm with official cutoffs on josaa.nic.in, mcc.nic.in, reap2025.com")

st.markdown("---")
st.markdown("""<div style="background:#0f172a;color:#cbd5e1;padding:10px;border-radius:8px;text-align:center;font-size:0.7rem;">🎓 UniSync - Steps 1-6 | Encrypted vault | Click-only AutoFill - always check every field before you submit</div>""", unsafe_allow_html=True)
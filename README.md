# ProofLens — Opportunity Verification & Threat Analysis

ProofLens is an evidence-based security utility designed to detect fraudulent recruitment schemes, unauthorized advance-fee demands, and domain impersonation within student and academic communications.

---

## Technical Overview

Fraudulent employment communications frequently exploit trusted brand names while redirecting applicants through unauthorized payment routes (e.g., registration deposits, training kit fees, laptop courier charges) and unmonitored channels (WhatsApp/Telegram).

ProofLens evaluates communication payloads using deterministic heuristic rules across five threat vectors:
1. **Advance Payment Demands (FIN-01):** Flags requests for candidate deposits, application fees, or training hardware charges.
2. **Sender Domain Integrity (IDN-02):** Detects usage of free public webmail (Gmail, Yahoo, Outlook) by senders claiming corporate entity affiliations.
3. **Destination Domain Reputation (NET-03):** Flags non-standard, disposable top-level domains (.xyz, .top, .work, .buzz) and temporary hosts.
4. **Assessment Process Integrity (PROC-04):** Identifies anomalous selection claims issued without interview or technical evaluation stages.
5. **Channel Auditing (CHAN-05):** Flags recruitment routed exclusively over unaudited messaging platforms.

---

## Interface & Usage

### 1. Standalone Web Dashboard
A zero-dependency, mobile-responsive client interface is implemented in `index.html`. It executes entirely within the local browser environment without sending input payloads to remote backends. Features full smartphone touch support, horizontal swipeable sample carousels, responsive typography, and viewport-fit formatting.

To inspect locally:
```bash
python -m http.server 8000
```
Open `http://localhost:8000` on desktop or your mobile device connected to the local network.

### 2. Streamlit Console
An interactive Python console is provided in `app.py`:
```bash
pip install -r requirements.txt
streamlit run app.py
```

---

## Privacy & Data Handling Specification

- **Zero Persistent Storage:** Submitted text payloads and uploaded files are processed strictly in-memory during active sessions. No communications or extracted PII are stored on disk or committed to databases.
- **Client-Side Execution:** The web dashboard executes heuristic evaluations locally within the browser.
- **No Model Training:** User submissions are never retained, logged, or utilized to train commercial models or classifiers.
- **No Tracking Telemetry:** Contains zero third-party advertising trackers or behavioral analytics pixels.

---

## Terms of Service & Legal Disclaimer

- **Informational & Diagnostic Utility:** Outputs and risk ratings are non-binding heuristic indicators designed to aid threat awareness. Users must independently verify offers with university placement directorates or corporate directories.
- **Nominative Trademark Usage:** Any mentions of corporate names (e.g. Microsoft, Infosys) are purely nominative to describe and identify potential impersonation vectors.
- **Permitted Purpose:** Authorized exclusively for personal verification, security research, and academic evaluation.

---

## Custom Domain Configuration

ProofLens is structured for production deployment behind a validated custom domain (e.g., via Cloudflare Pages, GitHub Pages, or a reverse proxy):

1. **DNS Setup:**
   - Configure a `CNAME` record pointing your custom domain (e.g. `verify.yourdomain.org`) to your hosting endpoint.
2. **TLS/SSL Enforcement:**
   - Enforce HTTPS and TLS 1.3 encryption across all communication pathways.
3. **HTTP Strict Transport Security (HSTS):**
   - Enable HSTS headers on the edge proxy to prevent protocol downgrade attacks.

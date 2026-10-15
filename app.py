"""
ProofLens — Opportunity Verification & Heuristic Threat Analysis
Technical Security Engine for Academic & Employment Communications
"""

import streamlit as st
import json
from verifier import ProofVerifier
from samples import SAMPLE_OFFERS

st.set_page_config(
    page_title="ProofLens — Opportunity Verification & Threat Analysis",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Polite, calm, warm-neutral styling (Zero purple gradients, zero emojis, zero harsh contrast)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 16px;
    }
    
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.9rem !important;
    }

    .header-bar {
        background-color: #ffffff;
        border: 1px solid #e7e5e4;
        padding: 1.5rem 1.75rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
    }

    .technical-card {
        background-color: #ffffff;
        border: 1px solid #e7e5e4;
        border-radius: 8px;
        padding: 1.1rem 1.25rem;
        margin-bottom: 0.85rem;
    }

    .status-pass {
        border-left: 4px solid #166534;
    }

    .status-fail {
        border-left: 4px solid #be123c;
    }

    .status-warn {
        border-left: 4px solid #b45309;
    }

    .tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        padding: 0.2rem 0.55rem;
        border-radius: 4px;
        font-weight: 600;
    }

    .tag-fail { background: #fff1f2; color: #9f1239; border: 1px solid #fecdd3; }
    .tag-pass { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
    .tag-warn { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
</style>
""", unsafe_allow_html=True)

# Navigation
with st.sidebar:
    st.subheader("ProofLens Console")
    st.caption("Verification & Threat Analysis Engine | v1.0")
    
    view_selection = st.radio(
        "Navigation",
        ["Threat Scanner", "Heuristic Methodology", "Privacy Policy", "Terms & Conditions"],
        index=0
    )
    
    st.divider()
    if view_selection == "Threat Scanner":
        st.write("**Evaluation Presets**")
        selected_preset = st.selectbox(
            "Load reference sample:",
            ["Select a sample..."] + list(SAMPLE_OFFERS.keys())
        )
    else:
        selected_preset = "Select a sample..."

    st.divider()
    st.caption("Custom Domain Deployment Ready")

# VIEW 1: THREAT SCANNER
if view_selection == "Threat Scanner":
    st.markdown("""
    <div class="header-bar">
        <h2 style="margin: 0; font-size: 1.35rem; font-weight: 600; color: #1c1917;">
            Opportunity Verification & Heuristic Threat Analysis
        </h2>
        <p style="margin: 0.35rem 0 0 0; color: #78716c; font-size: 0.875rem;">
            Inspect communication payloads for advance fee demands, domain spoofing patterns, and unmonitored channel routing.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([5, 4])

    with col1:
        st.write("##### Input Communication Payload")
        initial_val = ""
        if selected_preset != "Select a sample...":
            initial_val = SAMPLE_OFFERS[selected_preset]
            
        notice_input = st.text_area(
            "Raw text content or email headers:",
            value=initial_val,
            height=250,
            placeholder="Paste communication text or offer notice here..."
        )
        
        file_up = st.file_uploader("Upload plain text payload (.txt, .log):", type=["txt", "log", "md"])
        if file_up is not None:
            try:
                notice_input = file_up.read().decode("utf-8")
                st.info(f"Loaded payload from '{file_up.name}'.")
            except Exception as e:
                st.error(f"File decoding error: {e}")

        execute_btn = st.button("Execute Verification", type="primary", use_container_width=True)

    with col2:
        st.write("##### Security Heuristics Overview")
        st.markdown("""
        The engine applies deterministic rules to detect:
        - **Advance Payment Requests:** Prohibits fee charges for kits, registration, or equipment.
        - **Domain Host Verification:** Enforces corporate domain matching for corporate identities.
        - **Selection Shortcuts:** Flags claims of direct hiring without technical screening.
        - **Channel Diversion:** Warns against recruitment limited exclusively to messaging apps.
        """)

    # Execution Results
    if execute_btn or (notice_input.strip() and selected_preset != "Select a sample..."):
        if not notice_input.strip():
            st.warning("No input provided. Enter text or load a reference sample to execute analysis.")
        else:
            verifier = ProofVerifier()
            result = verifier.verify(notice_input)
            
            st.divider()
            st.write("#### Verification Report")
            
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Risk Score", f"{result['trust_score']}/100")
            with m2:
                st.metric("Assessed Status", result["overall_verdict"])
            with m3:
                st.metric("Rule Violations", result["red_flags_count"])
            with m4:
                companies = result["entities"]["companies"]
                st.metric("Claimed Entity", companies[0] if companies else "None Detected")

            st.write(f"**Analysis Summary:** {result['summary_statement']}")

            st.write("##### Heuristic Findings")
            for c in result["claims"]:
                status_class = "status-pass" if c["verdict"] == "PASS" else ("status-fail" if c["verdict"] == "FAIL" else "status-warn")
                tag_class = "tag-pass" if c["verdict"] == "PASS" else ("tag-fail" if c["verdict"] == "FAIL" else "tag-warn")
                
                st.markdown(f"""
                <div class="technical-card {status_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                        <span style="font-weight: 600; color: #1c1917; font-size: 0.85rem;">
                            {c["category"]}: {c["claim"]}
                        </span>
                        <span class="tag {tag_class}">{c["verdict"]}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #44403c; margin-bottom: 0.3rem;">
                        <strong>Evidence:</strong> {c["evidence"]}
                    </div>
                    <div style="font-size: 0.75rem; color: #78716c;">
                        <strong>Protocol:</strong> {c["action"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.download_button(
                "Export Audit Findings (JSON)",
                data=json.dumps(result, indent=2),
                file_name="prooflens_audit_report.json",
                mime="application/json"
            )

# VIEW 2: METHODOLOGY
elif view_selection == "Heuristic Methodology":
    st.markdown("""
    <div class="header-bar">
        <h2 style="margin: 0; font-size: 1.35rem; font-weight: 600; color: #1c1917;">
            Heuristic Methodology & Threat Detection Framework
        </h2>
        <p style="margin: 0.35rem 0 0 0; color: #78716c; font-size: 0.875rem;">
            Deterministic rule specifications implemented in the ProofLens analysis engine.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### 1. Advance Fee Demands (Rule ID: FIN-01)
    - **Logic:** Matches patterns requesting candidate deposits, processing fees, equipment delivery fees, or training costs.
    - **Rationale:** Legitimate enterprise recruitment does not require applicants to transfer funds under any pretext.

    ### 2. Sender Domain Integrity (Rule ID: IDN-02)
    - **Logic:** Identifies when communications claiming affiliation with known enterprise organizations originate from public free mail services (Gmail, Yahoo, Outlook, etc.).
    - **Rationale:** Corporate recruiting departments communicate through verified organizational domains equipped with SPF/DKIM records.

    ### 3. Destination Domain Reputation (Rule ID: NET-03)
    - **Logic:** Flags low-cost disposable TLDs (.xyz, .top, .work, .buzz) and temporary hosting services.
    - **Rationale:** Frequently utilized in short-lived phishing campaigns to harvest student credentials.

    ### 4. Process Integrity (Rule ID: PROC-04)
    - **Logic:** Flags offers that claim selection occurred without interviews, assessments, or screening.
    - **Rationale:** Unrealistic employment shortcuts are a primary characteristic of advance-fee recruitment schemes.
    """)

# VIEW 3: PRIVACY POLICY
elif view_selection == "Privacy Policy":
    st.markdown("""
    <div class="header-bar">
        <h2 style="margin: 0; font-size: 1.35rem; font-weight: 600; color: #1c1917;">
            Privacy Policy & Data Protection Specification
        </h2>
        <p style="margin: 0.35rem 0 0 0; color: #78716c; font-size: 0.875rem;">
            Last Updated: October 2026 | Production Compliance Standard
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### 1. Zero Persistent Storage
    ProofLens executes strictly in-memory during active inspection sessions. No submitted text, resumes, offer letters, or extracted entities (names, email addresses, phone numbers) are written to persistent disk storage or stored in databases.

    ### 2. Ephemeral Processing
    All parsed tokens and heuristic evaluations exist only for the duration required to generate the audit report and are cleared upon page refresh or session termination.

    ### 3. No Model Training on User Data
    User-submitted materials are never collected, logged, or utilized to fine-tune machine learning models or commercial classifiers.

    ### 4. Zero Third-Party Trackers
    This application does not bundle marketing analytics, user profiling pixels, or cross-site tracking beacons.

    ### 5. Custom Domain Configuration Notice
    This security utility is structured for deployment behind validated custom domain names with forced TLS 1.3 encryption.
    """)

# VIEW 4: TERMS & CONDITIONS
elif view_selection == "Terms & Conditions":
    st.markdown("""
    <div class="header-bar">
        <h2 style="margin: 0; font-size: 1.35rem; font-weight: 600; color: #1c1917;">
            Terms and Conditions of Use
        </h2>
        <p style="margin: 0.35rem 0 0 0; color: #78716c; font-size: 0.875rem;">
            Last Updated: October 2026 | Production Compliance Standard
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### 1. Analytical Purpose
    ProofLens is an analytical, evidence-based threat detection and verification system. It evaluates communications against heuristic rules to assist users in identifying fraudulent recruitment and advance-fee solicitation schemes.

    ### 2. Informational & Non-Advisory Nature
    The diagnostic results, risk scores, and recommendations generated by ProofLens are provided solely for general informational and threat-awareness purposes. ProofLens does not provide legal, financial, or formal employment advice. Users are required to independently verify any communication directly through official corporate career portals or university Training & Placement authorities.

    ### 3. Permitted & Acceptable Use
    You agree to utilize ProofLens exclusively for lawful purposes, such as analyzing suspicious emails, notices, or offers received by you or your academic institution. You agree not to attempt to disrupt, denial-of-service, or systematically exploit the verification endpoints.

    ### 4. Nominative Use of Corporate Names
    References to corporate names, brand names, or trademarks (such as Microsoft, Google, Infosys, etc.) within the tool are used strictly in a nominative capacity to identify, report, and analyze impersonation patterns. ProofLens is not affiliated with, sponsored by, or endorsed by these third-party organizations.

    ### 5. Limitation of Liability
    ProofLens and its developers provide this platform on an "as is" and "as available" basis without warranties of any kind. Under no circumstances shall ProofLens be liable for any direct, indirect, incidental, or consequential damages resulting from decisions made based on heuristic outputs.
    """)

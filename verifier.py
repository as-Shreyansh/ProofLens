"""
ProofLens - Evidence-Based Claim & Opportunity Verification Engine
Cybersecurity & Digital Trust Hackathon Project
"""

import os
import re
import json
import base64
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional

# Known legitimate corporate career domains vs free mail providers
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
    "protonmail.com", "icloud.com", "mail.com", "yandex.com", "zoho.com"
}

KNOWN_TECH_FIRMS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.jobs",
    "infosys": "infosys.com",
    "tcs": "tcs.com",
    "wipro": "wipro.com",
    "accenture": "accenture.com",
    "meta": "meta.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "ibm": "ibm.com",
    "cognizant": "cognizant.com",
    "capgemini": "capgemini.com",
    "adobe": "adobe.com",
    "cisco": "cisco.com",
    "oracle": "oracle.com"
}

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".buzz", ".live", ".fit", ".icu"]

FEE_RED_FLAGS = [
    r"(?:security|registration|training|application|processing|kit|laptop|equipment|id\s*card|documentation)\s*(?:deposit|fee|charge|amount|payment)",
    r"(?:pay|deposit|transfer|send)\s*(?:rs\.?|inr|₹|\$)\s*[\d,]+",
    r"refundable\s*(?:deposit|fee|amount)",
    r"(?:gpay|phonepe|paytm|upi\s*id|qr\s*code)",
    r"fee\s*is\s*100%\s*refundable"
]

URGENCY_PATTERNS = [
    r"(?:urgent|immediately|within\s*\d+\s*(?:hours|hrs|mins|minutes)|hurry|limited\s*seats|last\s*chance|expires\s*today)",
    r"(?:accept|reply|pay)\s*within\s*\d+\s*(?:hours|hrs|hours|days)"
]

UNREALISTIC_PERKS = [
    r"(?:direct\s*selection|no\s*interview|selection\s*without\s*interview|direct\s*joining)",
    r"(?:work\s*from\s*home|part\s*time).*?(?:earn|salary|stipend).*?(?:[\d,]{5,}|50000|40000|60000)",
    r"(?:guaranteed\s*placement|100%\s*job\s*guarantee|no\s*skills\s*required)"
]

CONTACT_RED_FLAGS = [
    r"(?:contact|reach|message|dm)\s*(?:us\s*)?(?:on|via)?\s*(?:whatsapp|telegram)\s*(?:only|directly|at)",
    r"t\.me/[a-zA-Z0-9_]+",
    r"wa\.me/[0-9]+"
]


class AIModelAdapter:
    """
    Modular, plug-and-play AI adapter.
    Supports Gemini, Groq, and OpenAI via standard REST calls so models can be
    swapped without rebuilding the verification pipeline.
    """

    SYSTEM_PROMPT = (
        "You are ProofLens AI, a cybersecurity threat intelligence engine specializing in "
        "academic and employment communications. Analyze the provided job/internship offer or "
        "communication payload (and optional image) for social engineering, pretexting, "
        "unrealistic compensation structures, linguistic manipulation, or brand impersonation.\n\n"
        "Respond strictly in valid JSON matching this schema:\n"
        "{\n"
        '  "ai_risk_deduction": <int between 0 and 50>,\n'
        '  "ai_red_flags": <int between 0 and 3>,\n'
        '  "ai_summary": "<1-2 sentence objective technical synthesis>",\n'
        '  "extracted_text_from_image": "<text if image provided, else empty string>",\n'
        '  "ai_claims": [\n'
        "    {\n"
        '      "category": "<e.g., Semantic Manipulation | Compensation Anomaly | Pretexting>",\n'
        '      "claim": "<concise description of the evaluated pattern>",\n'
        '      "verdict": "<PASS | CAUTION | FAIL>",\n'
        '      "status": "<verified | moderate_risk | high_risk>",\n'
        '      "evidence": "<specific analytical evidence from the payload>",\n'
        '      "action": "<recommended security protocol>"\n'
        "    }\n"
        "  ]\n"
        "}"
    )

    @classmethod
    def analyze(
        cls,
        provider: str,
        api_key: str,
        text: str,
        entities: Dict[str, Any],
        image_bytes: Optional[bytes] = None,
        image_mime: str = "image/png"
    ) -> Dict[str, Any]:
        provider_key = provider.lower()
        user_payload = (
            f"Communication Payload:\n{text if text.strip() else '[See attached image]'}\n\n"
            f"Pre-extracted Entities: {json.dumps(entities)}"
        )

        if "gemini" in provider_key:
            return cls._call_gemini(api_key, user_payload, image_bytes, image_mime)
        elif "groq" in provider_key:
            return cls._call_openai_compatible(
                url="https://api.groq.com/openai/v1/chat/completions",
                model="llama-3.3-70b-versatile",
                api_key=api_key,
                user_payload=user_payload
            )
        elif "openai" in provider_key:
            return cls._call_openai_compatible(
                url="https://api.openai.com/v1/chat/completions",
                model="gpt-4o-mini",
                api_key=api_key,
                user_payload=user_payload
            )
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")

    @classmethod
    def _call_gemini(
        cls,
        api_key: str,
        user_payload: str,
        image_bytes: Optional[bytes] = None,
        image_mime: str = "image/png"
    ) -> Dict[str, Any]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
        parts: List[Dict[str, Any]] = [{"text": f"{cls.SYSTEM_PROMPT}\n\n{user_payload}"}]

        if image_bytes:
            parts.append({
                "inlineData": {
                    "mimeType": image_mime,
                    "data": base64.b64encode(image_bytes).decode("utf-8")
                }
            })

        payload = {
            "contents": [{"parts": parts}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=25) as response:
            resp_data = json.loads(response.read().decode("utf-8"))
            raw_text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(raw_text)

    @classmethod
    def _call_openai_compatible(
        cls,
        url: str,
        model: str,
        api_key: str,
        user_payload: str
    ) -> Dict[str, Any]:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": cls.SYSTEM_PROMPT},
                {"role": "user", "content": user_payload}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "ProofLens-SecurityEngine/1.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=25) as response:
            resp_data = json.loads(response.read().decode("utf-8"))
            raw_text = resp_data["choices"][0]["message"]["content"]
            return json.loads(raw_text)


class ProofVerifier:
    def __init__(
        self,
        use_ai: bool = False,
        api_key: Optional[str] = None,
        provider: str = "Gemini 2.5 Flash"
    ):
        self.use_ai = use_ai
        self.provider = provider
        self.api_key = (
            api_key
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("GROQ_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        )

    def extract_entities(self, text: str) -> Dict[str, Any]:
        """Extract key entities from the notice text."""
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
        phones = re.findall(r'(?:\+91[\-\s]?)?[6789]\d{9}', text)
        money = re.findall(r'(?:₹|rs\.?|inr|\$)\s*[\d,]+(?:\.\d+)?', text, re.IGNORECASE)

        found_companies = []
        lower_text = text.lower()
        for company in KNOWN_TECH_FIRMS.keys():
            if re.search(r'\b' + re.escape(company) + r'\b', lower_text):
                found_companies.append(company.capitalize())

        return {
            "emails": list(set(emails)),
            "urls": list(set(urls)),
            "phones": list(set(phones)),
            "money": list(set(money)),
            "companies": found_companies
        }

    def verify(
        self,
        text: str,
        image_bytes: Optional[bytes] = None,
        image_mime: str = "image/png"
    ) -> Dict[str, Any]:
        """Perform full evidence-based claim verification (Deterministic + Optional AI Layer)."""
        ai_status = {
            "enabled": self.use_ai,
            "provider": self.provider,
            "executed": False,
            "summary": None,
            "error": None
        }
        ai_result = None

        # Pre-run AI if an image is uploaded without text so OCR text can feed into heuristics
        if self.use_ai and self.api_key and image_bytes and not text.strip():
            try:
                ai_result = AIModelAdapter.analyze(
                    provider=self.provider,
                    api_key=self.api_key,
                    text=text,
                    entities={},
                    image_bytes=image_bytes,
                    image_mime=image_mime
                )
                ocr_text = ai_result.get("extracted_text_from_image", "")
                if ocr_text:
                    text = ocr_text
                ai_status["executed"] = True
            except Exception as e:
                ai_status["error"] = str(e)

        entities = self.extract_entities(text)
        lower_text = text.lower()
        claims = []
        score_deductions = 0
        red_flags_count = 0
        positive_signals = 0

        # 1. Verification of Payment / Fee Demand (Crucial Signal)
        fee_matches = []
        for pat in FEE_RED_FLAGS:
            m = re.findall(pat, lower_text)
            if m:
                fee_matches.extend(m)

        if fee_matches:
            red_flags_count += 2
            score_deductions += 45
            claims.append({
                "category": "Financial Demand",
                "claim": "Candidate requested to pay fee/deposit",
                "verdict": "FAIL",
                "status": "critical_risk",
                "evidence": f"Found fee request patterns: '{fee_matches[0]}'. Legitimate employers and university internships NEVER charge candidates for training kits, application forms, or security deposits.",
                "action": "DO NOT send money or UPI payments under any circumstances."
            })
        else:
            positive_signals += 1
            claims.append({
                "category": "Financial Policy",
                "claim": "No candidate fee requested",
                "verdict": "PASS",
                "status": "verified",
                "evidence": "No upfront payment, registration fee, or security deposit requested in the text.",
                "action": "Consistent with genuine recruitment standards."
            })

        # 2. Verification of Recruiter Email & Domain
        if entities["emails"]:
            for email in entities["emails"]:
                domain = email.split("@")[-1].lower()
                if domain in FREE_EMAIL_PROVIDERS:
                    red_flags_count += 1
                    score_deductions += 30
                    matched_company = entities["companies"][0] if entities["companies"] else "an organization"
                    claims.append({
                        "category": "Recruiter Identity",
                        "claim": f"Recruiter contact ({email})",
                        "verdict": "FAIL",
                        "status": "high_risk",
                        "evidence": f"Recruiter is using a free public mail provider ({domain}) while purporting to represent {matched_company}. Corporate HR teams only use official company domain emails (e.g. @{domain.split('.')[0]}.com).",
                        "action": "Do not treat free mail addresses as official corporate communication."
                    })
                else:
                    positive_signals += 1
                    claims.append({
                        "category": "Recruiter Identity",
                        "claim": f"Official domain email ({email})",
                        "verdict": "PASS",
                        "status": "verified",
                        "evidence": f"Recruiter is using an institutional or corporate domain (@{domain}) instead of a public Gmail/Yahoo account.",
                        "action": "Check that the domain is the primary company career site."
                    })
        else:
            claims.append({
                "category": "Recruiter Identity",
                "claim": "No official recruiter email specified",
                "verdict": "CAUTION",
                "status": "unverified",
                "evidence": "No clear official corporate email address found in the notice.",
                "action": "Always verify the sender's identity through official channels."
            })

        # 3. Impersonation & Domain Check
        if entities["companies"]:
            company_name = entities["companies"][0]
            official_domain = KNOWN_TECH_FIRMS.get(company_name.lower())

            has_mismatch = False
            for url in entities["urls"]:
                if official_domain and official_domain not in url.lower():
                    has_mismatch = True
                    break

            if has_mismatch or (entities["emails"] and any(official_domain not in em for em in entities["emails"])):
                score_deductions += 20
                red_flags_count += 1
                claims.append({
                    "category": "Brand Impersonation",
                    "claim": f"Claimed affiliation with {company_name}",
                    "verdict": "FAIL",
                    "status": "high_risk",
                    "evidence": f"Notice claims to be from {company_name}, but does not provide an official '{official_domain}' communication channel or application URL.",
                    "action": f"Visit the official {company_name} careers portal ({official_domain}) directly to confirm this job listing."
                })
            else:
                claims.append({
                    "category": "Brand Verification",
                    "claim": f"Mention of {company_name}",
                    "verdict": "PASS",
                    "status": "verified",
                    "evidence": f"Identified recognizable organization: {company_name}.",
                    "action": f"Confirm opening ID on https://{official_domain}."
                })

        # 3b. URL & Domain Authenticity Check
        if entities["urls"]:
            for u in entities["urls"]:
                u_lower = u.lower()
                has_suspicious_tld = any(tld in u_lower for tld in SUSPICIOUS_TLDS)
                is_temp_site = "temp" in u_lower or "free" in u_lower or ".xyz" in u_lower
                if has_suspicious_tld or is_temp_site:
                    score_deductions += 25
                    red_flags_count += 1
                    claims.append({
                        "category": "Domain Authenticity",
                        "claim": f"Application URL ({u})",
                        "verdict": "FAIL",
                        "status": "high_risk",
                        "evidence": f"URL points to a temporary, free-tier, or suspicious TLD ({u}). Authentic organizations host career forms on dedicated corporate domains or established ATS platforms (Workday, Greenhouse, Lever).",
                        "action": "Do not enter credentials, resume data, or identity documents into unverified web forms."
                    })
                else:
                    claims.append({
                        "category": "Domain Authenticity",
                        "claim": f"External link ({u})",
                        "verdict": "PASS",
                        "status": "verified",
                        "evidence": "URL does not contain known throwaway or suspicious TLD patterns.",
                        "action": "Check browser SSL padlock before submitting details."
                    })

        # 4. Selection Process & Unrealistic Perks
        process_flags = []
        for pat in UNREALISTIC_PERKS:
            m = re.findall(pat, lower_text)
            if m:
                process_flags.extend(m)

        if process_flags:
            score_deductions += 20
            red_flags_count += 1
            claims.append({
                "category": "Hiring Process",
                "claim": "Offer issued without formal assessment",
                "verdict": "FAIL",
                "status": "high_risk",
                "evidence": "Mention of direct selection, no interview, or unrealistically high pay without skill verification. Real technical roles require screening interviews or coding tests.",
                "action": "Be cautious of job offers extended without any technical evaluation."
            })
        else:
            claims.append({
                "category": "Hiring Process",
                "claim": "Standard recruitment requirements",
                "verdict": "PASS",
                "status": "verified",
                "evidence": "No red-flag shortcuts ('direct selection', 'no interview required') detected.",
                "action": "Verify the interview stages with the hiring team."
            })

        # 5. Artificial Urgency & High-Pressure Tactics
        urgency_matches = []
        for pat in URGENCY_PATTERNS:
            m = re.findall(pat, lower_text)
            if m:
                urgency_matches.extend(m)

        if urgency_matches:
            score_deductions += 15
            claims.append({
                "category": "Urgency & Pressure",
                "claim": "High-pressure acceptance deadline",
                "verdict": "CAUTION",
                "status": "moderate_risk",
                "evidence": f"Found urgency triggers: '{urgency_matches[0]}'. Scammers use extreme deadlines (e.g., 'respond in 2 hours') to prevent candidates from verifying claims with mentors or college TPOs.",
                "action": "Take your time to consult your College Training & Placement Cell (TPO) before responding."
            })

        # 6. Informal Communication Channels (WhatsApp / Telegram Only)
        contact_flags = []
        for pat in CONTACT_RED_FLAGS:
            m = re.findall(pat, lower_text)
            if m:
                contact_flags.extend(m)

        if contact_flags:
            score_deductions += 15
            red_flags_count += 1
            claims.append({
                "category": "Channel Security",
                "claim": "Direct recruitment exclusively over WhatsApp/Telegram",
                "verdict": "FAIL",
                "status": "moderate_risk",
                "evidence": "Recruitment redirected exclusively through Telegram or personal WhatsApp. Legitimate corporate recruitment happens via official applicant tracking systems (Workday, Greenhouse, Taleo) or corporate email.",
                "action": "Never conduct official hiring or onboarding solely through anonymous messaging apps."
            })

        # 7. Modular AI Deep Inspection Layer
        if self.use_ai:
            if not self.api_key:
                ai_status["error"] = "API key not provided. Falling back to deterministic heuristics."
            else:
                try:
                    if ai_result is None:
                        ai_result = AIModelAdapter.analyze(
                            provider=self.provider,
                            api_key=self.api_key,
                            text=text,
                            entities=entities,
                            image_bytes=image_bytes,
                            image_mime=image_mime
                        )
                    ai_status["executed"] = True
                    ai_status["summary"] = ai_result.get("ai_summary")

                    ai_deduction = int(ai_result.get("ai_risk_deduction", 0))
                    ai_flags = int(ai_result.get("ai_red_flags", 0))
                    score_deductions += max(0, min(50, ai_deduction))
                    red_flags_count += max(0, min(3, ai_flags))

                    for ai_claim in ai_result.get("ai_claims", []):
                        claims.append({
                            "category": f"AI Threat Engine — {ai_claim.get('category', 'Contextual Analysis')}",
                            "claim": ai_claim.get("claim", "Semantic pattern inspection"),
                            "verdict": ai_claim.get("verdict", "CAUTION"),
                            "status": ai_claim.get("status", "moderate_risk"),
                            "evidence": ai_claim.get("evidence", "Identified by LLM semantic inspection."),
                            "action": ai_claim.get("action", "Verify independently via official channels.")
                        })
                except Exception as e:
                    ai_status["error"] = f"AI inspection failed ({e}). Showing deterministic heuristic results."

        # Compute Trust Score (0 to 100)
        trust_score = max(5, min(100, 100 - score_deductions))
        if red_flags_count >= 2:
            trust_score = min(trust_score, 30)

        if trust_score < 40:
            overall_verdict = "HIGH RISK - LIKELY SCAM"
            badge_color = "red"
            summary_statement = "This notice exhibits multiple critical red flags typical of fraudulent employment scams. Exercise extreme caution and do not transfer funds or sensitive personal documents."
        elif trust_score < 75:
            overall_verdict = "SUSPICIOUS - PROCEED WITH CAUTION"
            badge_color = "yellow"
            summary_statement = "Some claims could not be verified or informal communication channels were used. Conduct secondary verification through your university TPO before proceeding."
        else:
            overall_verdict = "LOW RISK - LIKELY LEGITIMATE"
            badge_color = "green"
            summary_statement = "No prominent scam patterns detected. The communication adheres to standard recruitment practices."

        if ai_status.get("summary"):
            summary_statement = f"{summary_statement} [AI Synthesis: {ai_status['summary']}]"

        return {
            "trust_score": trust_score,
            "overall_verdict": overall_verdict,
            "badge_color": badge_color,
            "summary_statement": summary_statement,
            "red_flags_count": red_flags_count,
            "entities": entities,
            "claims": claims,
            "ai_status": ai_status
        }

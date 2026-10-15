"""
ProofLens - Evidence-Based Claim & Opportunity Verification Engine
Cybersecurity & Digital Trust Hackathon Project
"""

import re
from typing import Dict, List, Any

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

class ProofVerifier:
    def __init__(self):
        pass

    def extract_entities(self, text: str) -> Dict[str, Any]:
        """Extract key entities from the notice text."""
        # Find emails
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        
        # Find URLs and domains
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
        
        # Find phone numbers
        phones = re.findall(r'(?:\+91[\-\s]?)?[6789]\d{9}', text)
        
        # Find monetary amounts
        money = re.findall(r'(?:₹|rs\.?|inr|\$)\s*[\d,]+(?:\.\d+)?', text, re.IGNORECASE)

        # Detect mentioned company names
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

    def verify(self, text: str) -> Dict[str, Any]:
        """Perform full evidence-based claim verification."""
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
            
            # Check if text contains misleading URLs
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
                        "evidence": f"URL does not contain known throwaway or suspicious TLD patterns.",
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

        return {
            "trust_score": trust_score,
            "overall_verdict": overall_verdict,
            "badge_color": badge_color,
            "summary_statement": summary_statement,
            "red_flags_count": red_flags_count,
            "entities": entities,
            "claims": claims
        }

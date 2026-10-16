"""
ProofLens - Unit Test Suite for Heuristic & AI Hybrid Verification Engine
"""

import pytest
from verifier import ProofVerifier, AIModelAdapter


def test_clean_payload_passes():
    """Verify that legitimate communications pass without critical flags."""
    verifier = ProofVerifier(use_ai=False)
    sample_text = (
        "Dear Candidate, Infosys Ltd. is pleased to extend an offer for Systems Engineer Intern. "
        "Official portal: https://www.infosys.com/careers. No fee is required."
    )
    result = verifier.verify(sample_text)
    
    assert result["trust_score"] >= 75
    assert result["overall_verdict"] == "LOW RISK - LIKELY LEGITIMATE"
    assert result["red_flags_count"] == 0


def test_advance_fee_scam_fails():
    """Verify that advance fee demands trigger critical risk scoring."""
    verifier = ProofVerifier(use_ai=False)
    scam_text = (
        "Congratulations! Send an upfront security deposit of Rs. 2,499 via UPI to "
        "hr.microsoft.onboarding@gmail.com for your laptop courier kit."
    )
    result = verifier.verify(scam_text)
    
    assert result["trust_score"] <= 40
    assert result["overall_verdict"] == "HIGH RISK - LIKELY SCAM"
    assert result["red_flags_count"] >= 2
    
    # Check that FIN-01 (Financial Demand) failed
    fin_claim = next((c for c in result["claims"] if c["category"] == "Financial Demand"), None)
    assert fin_claim is not None
    assert fin_claim["verdict"] == "FAIL"


def test_free_mail_spoofing_detected():
    """Verify that corporate impersonation using public webmail is flagged."""
    verifier = ProofVerifier(use_ai=False)
    spoof_text = "We represent Google. Contact our recruiter at recruiter.google.jobs@gmail.com"
    result = verifier.verify(spoof_text)
    
    id_claim = next((c for c in result["claims"] if c["category"] == "Recruiter Identity"), None)
    assert id_claim is not None
    assert id_claim["verdict"] == "FAIL"


def test_ai_adapter_mock_schema():
    """Verify AI adapter system prompt schema structure requirement."""
    assert "ProofLens AI" in AIModelAdapter.SYSTEM_PROMPT
    assert "ai_risk_deduction" in AIModelAdapter.SYSTEM_PROMPT
    assert "ai_claims" in AIModelAdapter.SYSTEM_PROMPT

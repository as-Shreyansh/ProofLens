from verifier import ProofVerifier
from samples import SAMPLE_OFFERS

v = ProofVerifier()
for name, text in SAMPLE_OFFERS.items():
    res = v.verify(text)
    print(f"Test: {name}")
    print(f"  Trust Score: {res['trust_score']}/100")
    print(f"  Verdict: {res['overall_verdict']}")
    print(f"  Red Flags: {res['red_flags_count']}")
    print(f"  Claims Analyzed: {len(res['claims'])}")
    print("-" * 50)

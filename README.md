# ProofLens — Opportunity Verification & Heuristic Threat Analysis

**ProofLens** is a technical security engine designed to inspect academic communications, internship notices, and employment offers for advance-fee scams, domain spoofing, unmonitored communication channels, and social engineering.

---

## Architecture: Hybrid Verification Engine

ProofLens operates on a robust **two-layer verification pipeline**:
1. **Layer 1 (Deterministic Heuristics):** Instantly evaluates payloads against regex rule signatures (`FIN-01`, `IDN-02`, `NET-03`, `PROC-04`, `CHAN-05`) for instantaneous, reliable threat detection.
2. **Layer 2 (Modular AI Threat Layer / LLM-06):** Optional plug-and-play adapter supporting **Google Gemini 2.5 Flash**, **Groq (Llama-3.3-70B)**, and **OpenAI (GPT-4o-mini)**. Inspects subtle psychological pretexting, urgency manipulation, and supports **multimodal offer screenshot verification**.

---

## Project Structure

```text
ProofLens/
├── app.py              # Streamlit Python backend & console interface
├── verifier.py         # Heuristics engine & modular AI model adapter
├── index.html          # Standalone frontend with Tailwind CSS & Motion.dev
├── samples.py          # Reference scam and legitimate communication presets
├── test_verifier.py    # Pytest unit test suite
└── README.md           # Technical specification & project documentation

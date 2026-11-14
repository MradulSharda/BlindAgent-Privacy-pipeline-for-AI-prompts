"""
Unit Tests for BlindAgent 4-Layer Ensemble Secret Detection.
Validates:
1. Deterministic RegEx & Explicit Enclave Tags (<secret>)
2. Sliding-Window Shannon Information Entropy (H(X))
3. Linear-Chain CRF Contextual & Morphological Sequence Tagger
4. Character N-Gram Markov Language Model Perplexity Outliers
5. Span Merging, Consensus Attribution, and Precedence
6. Benign Vocabulary Safeguards (Zero False-Positives on Standard Syntax)
7. End-to-End Integration with SemanticBlinder & Lagrange Reconstruction
"""

import math
import pytest
from blindagent.detectors import (
    RegexDetector,
    ShannonEntropyDetector,
    CRFProbabilisticDetector,
    MarkovNgramModelDetector,
    MultiDetectorEnsemble,
    merge_spans,
    DetectedSpan,
    BENIGN_WORDS
)
from blindagent.blinder import SemanticBlinder
from blindagent.sss import ShamirSecretSharing


def test_regex_detector_patterns():
    detector = RegexDetector()

    # Explicit <secret> tag
    text1 = "Deploy cluster using <secret>super-isolated-passphrase-88</secret> now."
    spans1 = detector.detect(text1)
    assert len(spans1) == 1
    assert spans1[0].entity_type == "EXPLICIT_SECRET"
    assert spans1[0].text == "super-isolated-passphrase-88"
    assert text1[spans1[0].start:spans1[0].end] == "<secret>super-isolated-passphrase-88</secret>"

    # SSN
    text2 = "Employee record SSN is 123-45-6789 in HR records."
    spans2 = detector.detect(text2)
    assert any(s.entity_type == "NATIONAL_ID" and s.text == "123-45-6789" for s in spans2)

    # Financial Value
    text3 = "Transfer balance $50,000 to primary checking."
    spans3 = detector.detect(text3)
    assert any(s.entity_type == "FINANCIAL_VALUE" and s.text == "$50,000" for s in spans3)

    # API Keys (OpenAI sk-..., AWS AKIA..., Gemini AIzaSy...)
    text4 = "OpenAI key sk-live99887766554433221100aa and AWS AKIAIOSFODNN7EXAMPLE."
    spans4 = detector.detect(text4)
    api_spans = [s for s in spans4 if s.entity_type == "API_KEY"]
    assert len(api_spans) == 2
    assert any("sk-live" in s.text for s in api_spans)
    assert any("AKIA" in s.text for s in api_spans)

    # Master Key Assignment
    text5 = "Database configuration master_key: VaultRootPassword99!"
    spans5 = detector.detect(text5)
    assert any(s.entity_type == "MASTER_SECRET" and s.text == "VaultRootPassword99!" for s in spans5)


def test_shannon_entropy_calculation_and_detection():
    detector = ShannonEntropyDetector(min_len=7, min_entropy=3.2)

    # Theoretical Entropy validation
    # Uniform 4-character alphabet: H(X) = -4 * (0.25 * log2(0.25)) = 2.0
    assert math.isclose(detector.calc_entropy("abcd"), 2.0, rel_tol=1e-5)
    # Monomorphic string: H(X) = 0.0
    assert detector.calc_entropy("aaaaaaaa") == 0.0

    # High entropy pseudorandom token
    high_entropy_token = "K9#vL!2pQz@1x"
    assert detector.calc_entropy(high_entropy_token) > 3.4

    prompt = f"Connect to internal worker with token {high_entropy_token}."
    spans = detector.detect(prompt)
    assert any(s.detector == "SHANNON_ENTROPY" and s.text == high_entropy_token for s in spans)

    # Repeating / low entropy token should NOT trigger
    low_prompt = "The status is standard running smoothly."
    assert len(detector.detect(low_prompt)) == 0


def test_crf_probabilistic_sequence_tagger():
    detector = CRFProbabilisticDetector()

    # Preceding context word "bearer" + morphological features (digits, symbols, mixed case)
    prompt = "Authorize request with bearer 9xK#m2$9pQ to access endpoint."
    spans = detector.detect(prompt)
    assert len(spans) >= 1
    assert any("9xK#m2$9pQ" in s.text for s in spans)
    assert spans[0].detector == "CRF_PROBABILISTIC"

    # Context trigger "token:"
    prompt2 = "Setting token: J87!kLmP90 for service account."
    spans2 = detector.detect(prompt2)
    assert any("J87!kLmP90" in s.text for s in spans2)


def test_markov_ngram_language_model():
    detector = MarkovNgramModelDetector()

    # Natural language query should have low perplexity and produce zero anomaly detections
    natural_query = "Please generate an audit query for employee records and balance retrieved from database"
    spans = detector.detect(natural_query)
    assert len(spans) == 0

    # Anomalous high-perplexity random token
    anomaly_token = "qxj89_#zmfk"
    ppl = detector.calc_perplexity(anomaly_token)
    assert ppl > 32.0

    prompt = f"Set connection string option {anomaly_token} on remote node"
    spans_anom = detector.detect(prompt)
    assert any(s.detector == "MARKOV_NGRAM" and s.text == anomaly_token for s in spans_anom)


def test_benign_words_safeguard():
    """
    Ensure standard SQL keywords, programming tokens, and query nouns
    are never falsely masked by any detector layer.
    """
    ensemble = MultiDetectorEnsemble()
    sql_prompt = (
        "SELECT employee, salary, department FROM payroll "
        "WHERE balance > 1000 AND status = 'active'"
    )
    spans = ensemble.scan_prompt(sql_prompt)
    # The only thing that might legitimately match is a financial value or number,
    # but none of the words 'SELECT', 'employee', 'salary', 'department', 'payroll', 'balance' should match!
    detected_words = {s.text.lower() for s in spans}
    for word in ["select", "employee", "salary", "department", "payroll", "balance", "where", "status"]:
        assert word not in detected_words, f"Benign word '{word}' was falsely detected!"


def test_span_merging_and_consensus():
    # Two overlapping spans from different detectors
    span1 = DetectedSpan(
        start=10, end=30, text="SecretToken12345",
        entity_type="HIGH_ENTROPY_SECRET", detector="SHANNON_ENTROPY", score=3.8
    )
    span2 = DetectedSpan(
        start=10, end=30, text="SecretToken12345",
        entity_type="CRF_SENSITIVE_ENTITY", detector="CRF_PROBABILISTIC", score=4.5
    )

    merged = merge_spans([span1, span2])
    assert len(merged) == 1
    assert merged[0].start == 10
    assert merged[0].end == 30
    # Both detectors recorded in consensus
    assert "CRF_PROBABILISTIC" in merged[0].detector
    assert "SHANNON_ENTROPY" in merged[0].detector

    # Explicit secret priority
    explicit_span = DetectedSpan(
        start=5, end=45, text="my-secret-key",
        entity_type="EXPLICIT_SECRET", detector="DETERMINISTIC_REGEX", score=1.0
    )
    inner_span = DetectedSpan(
        start=13, end=26, text="my-secret-key",
        entity_type="HIGH_ENTROPY_SECRET", detector="SHANNON_ENTROPY", score=3.9
    )
    merged_exp = merge_spans([explicit_span, inner_span])
    assert len(merged_exp) == 1
    assert merged_exp[0].entity_type == "EXPLICIT_SECRET"
    assert merged_exp[0].start == 5
    assert merged_exp[0].end == 45


def test_blinder_ensemble_full_roundtrip():
    """
    Validates end-to-end mathematical blinding, zero-plaintext storage,
    and Lagrange SSS unblinding across multi-detector entities.
    """
    blinder = SemanticBlinder(sss_threshold=3, sss_total=5)
    prompt = (
        "Authorize transfer of $75,000 for patient SSN: 987-65-4321 "
        "using auth_token: sk-live99887766554433221100aa and "
        "<secret>vault-enclave-passphrase-2026</secret>."
    )

    blinded_prompt, entities = blinder.blind_prompt(prompt)

    # 1. Plaintext secrets must NOT appear on the wire
    assert "987-65-4321" not in blinded_prompt
    assert "$75,000" not in blinded_prompt
    assert "sk-live99887766554433221100aa" not in blinded_prompt
    assert "vault-enclave-passphrase-2026" not in blinded_prompt
    assert "<secret>" not in blinded_prompt

    # 2. Vault must NEVER store original plaintext
    for token_id, entity in blinder.vault.items():
        assert not hasattr(entity, "original_value")
        assert not hasattr(entity, "plaintext")
        # Lagrange SSS reconstruction recovers exact secret
        recovered_sss = entity.reconstruct_secret(blinder.sss)
        # Affine GF(2^8) inversion recovers exact secret
        recovered_aff = entity.unblind_affine_secret()
        assert recovered_sss == recovered_aff
        assert len(recovered_sss) > 0

    # 3. Simulate host LLM response echoing blinded tokens
    mock_host_response = f"Confirmed authorization for {list(blinder.vault.keys())[0]}."
    unblinded_response = blinder.unblind_response(mock_host_response)

    # Recovered response must contain the real secret
    first_entity = list(blinder.vault.values())[0]
    first_secret = first_entity.reconstruct_secret(blinder.sss)
    assert first_secret in unblinded_response
    assert "BLIND_TOKEN" not in unblinded_response


if __name__ == "__main__":
    test_regex_detector_patterns()
    test_shannon_entropy_calculation_and_detection()
    test_crf_probabilistic_sequence_tagger()
    test_markov_ngram_language_model()
    test_benign_words_safeguard()
    test_span_merging_and_consensus()
    test_blinder_ensemble_full_roundtrip()
    print("All 4-Layer Ensemble Secret Detection tests PASSED 100%!")

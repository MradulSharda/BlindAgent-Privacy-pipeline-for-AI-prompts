"""
Multi-Paradigm Sensitive Entity Detection for BlindAgent.
Combines 4 independent detection layers:
1. Deterministic / RegEx & Explicit Enclave Tags
2. Sliding-Window Shannon Information Entropy (H(X))
3. Linear-Chain CRF / Probabilistic Sequence Tagger
4. Character N-Gram Markov Language Model (Perplexity Anomaly)
"""

import re
import math
from collections import Counter
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass


@dataclass
class DetectedSpan:
    start: int
    end: int
    text: str
    entity_type: str
    detector: str
    score: float = 1.0


# Benign vocabulary to avoid false positives on common syntax/prompt words
BENIGN_WORDS = {
    "password", "master_key", "token", "secret", "auth_bearer", "transfer", "query",
    "select", "where", "from", "employee", "payroll", "database", "balance", "records", "retrieved",
    "clinical", "summary", "transaction", "limit", "approved", "patient", "holding",
    "authorized", "generate", "please", "system", "report", "salary", "account", "status",
    "insert", "update", "delete", "create", "table", "function", "return", "constant",
    "number", "string", "boolean", "object", "server", "client", "enclave", "pipeline",
    "access", "requested", "bearer", "login", "admin", "service", "model", "cloud", "audit",
    "public", "private", "protect", "shield", "execute", "values", "department", "hospital"
}


# =====================================================================
# LAYER 1: Deterministic Lexical & Explicit Enclave Tags
# =====================================================================
class RegexDetector:
    PATTERNS = [
        # Explicit tag <secret>...</secret>
        (r"<secret>(.*?)</secret>", "EXPLICIT_SECRET", True),
        # API Keys (AWS, OpenAI, Gemini, GitHub)
        (r"\b(?:sk-[a-zA-Z0-9]{20,}|AIzaSy[a-zA-Z0-9_\-]{33}|AKIA[0-9A-Z]{16})\b", "API_KEY", False),
        # Master Key or Passwords assignments
        (r"(?i)\b(?:master_key|api_secret|password|db_pass)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*_\-]+)['\"]?", "MASTER_SECRET", False),
        # SSN
        (r"\b\d{3}-\d{2}-\d{4}\b", "NATIONAL_ID", False),
        # Credit Card (13-16 digits with dashes or spaces)
        (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "PAYMENT_CARD", False),
        # Financial amounts
        (r"\$\d+(?:,\d{3})*(?:\.\d{2})?", "FINANCIAL_VALUE", False),
    ]

    def detect(self, text: str) -> List[DetectedSpan]:
        spans = []
        for pat, etype, is_explicit in self.PATTERNS:
            for m in re.finditer(pat, text):
                if is_explicit:
                    spans.append(DetectedSpan(
                        start=m.start(),
                        end=m.end(),
                        text=m.group(1),
                        entity_type=etype,
                        detector="DETERMINISTIC_REGEX",
                        score=1.0
                    ))
                elif m.lastindex and m.lastindex >= 1:
                    secret_val = m.group(1)
                    s_idx = m.start(1)
                    e_idx = m.end(1)
                    spans.append(DetectedSpan(
                        start=s_idx,
                        end=e_idx,
                        text=secret_val,
                        entity_type=etype,
                        detector="DETERMINISTIC_REGEX",
                        score=1.0
                    ))
                else:
                    spans.append(DetectedSpan(
                        start=m.start(),
                        end=m.end(),
                        text=m.group(0),
                        entity_type=etype,
                        detector="DETERMINISTIC_REGEX",
                        score=1.0
                    ))
        return spans


# =====================================================================
# LAYER 2: Sliding-Window Shannon Information Entropy (H(X))
# =====================================================================
class ShannonEntropyDetector:
    """
    Computes character entropy: H(X) = -sum(p * log2(p)).
    High entropy (randomness) indicates cryptographic keys, hashes, and secure passwords.
    """
    def __init__(self, min_len: int = 7, min_entropy: float = 3.2):
        self.min_len = min_len
        self.min_entropy = min_entropy

    @staticmethod
    def calc_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        total = len(s)
        ent = 0.0
        for cnt in counts.values():
            p = cnt / total
            ent -= p * math.log2(p)
        return ent

    def detect(self, text: str) -> List[DetectedSpan]:
        spans = []
        for m in re.finditer(r"[A-Za-z0-9!@#$%^&*_\-\.]{6,}", text):
            raw_token = m.group(0)
            token = raw_token.strip(".,!?:;'\"()[]{}")
            if len(token) < self.min_len or token.lower() in BENIGN_WORDS:
                continue

            has_upper = any(c.isupper() for c in token)
            has_lower = any(c.islower() for c in token)
            has_digit = any(c.isdigit() for c in token)
            has_sym = any(not c.isalnum() for c in token)
            variety_score = sum([has_upper, has_lower, has_digit, has_sym])

            entropy = self.calc_entropy(token)
            is_hex = re.fullmatch(r"[0-9a-fA-F]{16,}", token) is not None

            # High entropy criteria:
            # - Very high entropy (>= 3.6 bits) and length >= 8
            # - High variety (>= 3 character classes) with entropy >= 3.2
            # - Uniform hex strings of >= 16 bytes
            if (entropy >= 3.6 and len(token) >= 8) or \
               (entropy >= self.min_entropy and variety_score >= 3 and len(token) >= 8) or \
               (is_hex and entropy >= 3.0):
                start_offset = m.start() + raw_token.find(token)
                end_offset = start_offset + len(token)
                spans.append(DetectedSpan(
                    start=start_offset,
                    end=end_offset,
                    text=token,
                    entity_type="HIGH_ENTROPY_SECRET",
                    detector="SHANNON_ENTROPY",
                    score=round(entropy, 2)
                ))
        return spans


# =====================================================================
# LAYER 3: Linear-Chain CRF / Probabilistic Sequence Tagger
# =====================================================================
class CRFProbabilisticDetector:
    """
    Probabilistic sequence tagger using contextual transition features
    and token morphological structures to identify sensitive parameters.
    """
    CONTEXT_TRIGGER_WORDS = {
        "key", "token", "password", "pass", "secret", "auth", "bearer", "pin", "ssn",
        "credential", "credentials", "api_key", "private", "access_key", "salt", "seed",
        "hash", "master_key", "client_secret", "jwt", "apikey", "auth_bearer", "secret_key"
    }

    def detect(self, text: str) -> List[DetectedSpan]:
        spans = []
        words = list(re.finditer(r"\S+", text))
        for i, m in enumerate(words):
            raw_w = m.group(0)
            w = raw_w.strip(".,!?:;'\"()[]{}:=")
            if not w or len(w) < 4 or w.lower() in BENIGN_WORDS:
                continue

            context_score = 0.0
            if i > 0:
                prev_w = words[i - 1].group(0).lower().strip(".,!?:;'\"()[]{}:=")
                if prev_w in self.CONTEXT_TRIGGER_WORDS:
                    context_score += 2.5
            if i > 1:
                prev_prev_w = words[i - 2].group(0).lower().strip(".,!?:;'\"()[]{}:=")
                if prev_prev_w in self.CONTEXT_TRIGGER_WORDS:
                    context_score += 1.5

            has_digit = any(c.isdigit() for c in w)
            has_upper = any(c.isupper() for c in w)
            has_sym = any(not c.isalnum() for c in w)
            length_feature = min(len(w) / 10.0, 2.0)
            digit_ratio = sum(c.isdigit() for c in w) / len(w)

            morpho_score = (1.0 if has_digit else 0.0) + \
                           (1.0 if has_upper else 0.0) + \
                           (1.5 if has_sym else 0.0) + \
                           length_feature + (digit_ratio * 2.0)

            total_crf_score = (context_score * 1.5) + morpho_score

            if (context_score > 0 and morpho_score >= 2.0) or (context_score >= 2.5):
                start_offset = m.start() + raw_w.find(w)
                end_offset = start_offset + len(w)
                spans.append(DetectedSpan(
                    start=start_offset,
                    end=end_offset,
                    text=w,
                    entity_type="CRF_SENSITIVE_ENTITY",
                    detector="CRF_PROBABILISTIC",
                    score=round(total_crf_score, 2)
                ))
        return spans


# =====================================================================
# LAYER 4: Character N-Gram Markov Language Model (Perplexity Anomaly)
# =====================================================================
class MarkovNgramModelDetector:
    """
    Character 3-gram Markov Model trained on natural code/English vocabulary.
    Anomalous high-perplexity tokens indicate random passwords, tokens, and hashes.
    """
    def __init__(self):
        corpus = (
            "the of and to a in is you that it he was for on are as with his they at be this have from or one had "
            "select from where insert into update delete table join inner left right group by order limit "
            "function return const let var import export class public private async await def self none true false "
            "employee salary id name user account department balance query diagnosis patient system authorized "
            "request response header status error exception message format string boolean number array object "
            "please generate an audit query records retrieved clinical summary transaction limit approved "
            "authorization credentials confidential parameters connect database execute executePipeline"
        )
        self.transitions: Dict[str, Dict[str, int]] = {}
        self.context_totals: Dict[str, int] = {}
        self.vocab: Set[str] = set(corpus.lower())

        for i in range(len(corpus) - 2):
            ctx = corpus[i:i+2].lower()
            nxt = corpus[i+2].lower()
            if ctx not in self.transitions:
                self.transitions[ctx] = Counter()
            self.transitions[ctx][nxt] += 1
            self.context_totals[ctx] = self.context_totals.get(ctx, 0) + 1

    def calc_perplexity(self, word: str) -> float:
        w = word.lower()
        if len(w) < 4:
            return 0.0
        log_prob_sum = 0.0
        n_transitions = 0
        vocab_size = len(self.vocab) + 20

        for i in range(len(w) - 2):
            ctx = w[i:i+2]
            nxt = w[i+2]
            ctx_cnt = self.context_totals.get(ctx, 0)
            nxt_cnt = self.transitions.get(ctx, {}).get(nxt, 0)
            prob = (nxt_cnt + 1.0) / (ctx_cnt + vocab_size)
            log_prob_sum += math.log(prob)
            n_transitions += 1

        if n_transitions == 0:
            return 0.0
        avg_neg_ll = -log_prob_sum / n_transitions
        return math.exp(avg_neg_ll)

    def detect(self, text: str) -> List[DetectedSpan]:
        spans = []
        words = list(re.finditer(r"\b[A-Za-z0-9_\-!@#$%^&*]{6,}\b", text))
        for m in words:
            w = m.group(0)
            if w.lower() in BENIGN_WORDS:
                continue
            ppl = self.calc_perplexity(w)
            if ppl > 32.0 and len(w) >= 7:
                spans.append(DetectedSpan(
                    start=m.start(),
                    end=m.end(),
                    text=w,
                    entity_type="MARKOV_ANOMALY_TOKEN",
                    detector="MARKOV_NGRAM",
                    score=round(ppl, 2)
                ))
        return spans


# =====================================================================
# SPAN MERGER & ENSEMBLE ORCHESTRATOR
# =====================================================================
def merge_spans(spans: List[DetectedSpan]) -> List[DetectedSpan]:
    """
    Merges overlapping detected spans into unified maximal spans.
    Accumulates detector consensus (e.g. 'DETERMINISTIC_REGEX + SHANNON_ENTROPY').
    """
    if not spans:
        return []

    # Sort primarily by start ascending, then length descending
    sorted_spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    merged: List[DetectedSpan] = []

    for cur in sorted_spans:
        if not merged:
            merged.append(cur)
            continue
        prev = merged[-1]

        # Check overlap
        if cur.start < prev.end:
            new_end = max(prev.end, cur.end)
            detectors_set = set(prev.detector.split(" + "))
            detectors_set.add(cur.detector)
            combined_detector = " + ".join(sorted(detectors_set))
            
            # Prefer explicit or specific entity types over generic ones
            entity_type = prev.entity_type
            if prev.entity_type in {"CRF_SENSITIVE_ENTITY", "MARKOV_ANOMALY_TOKEN"} and cur.entity_type not in {"CRF_SENSITIVE_ENTITY", "MARKOV_ANOMALY_TOKEN"}:
                entity_type = cur.entity_type
            elif prev.entity_type == "EXPLICIT_SECRET":
                entity_type = "EXPLICIT_SECRET"

            merged[-1] = DetectedSpan(
                start=prev.start,
                end=new_end,
                text=cur.text,
                entity_type=entity_type,
                detector=combined_detector,
                score=max(prev.score, cur.score)
            )
        else:
            merged.append(cur)

    return merged


class MultiDetectorEnsemble:
    """
    Passes the whole prompt through all 4 detectors:
    1. Deterministic / RegEx & Explicit tags
    2. Shannon Entropy Window
    3. Linear-Chain CRF Probabilistic Tagger
    4. Character N-Gram Markov Model
    Returns the unified, deduplicated list of detected sensitive entities.
    """
    def __init__(self):
        self.d1_regex = RegexDetector()
        self.d2_entropy = ShannonEntropyDetector()
        self.d3_crf = CRFProbabilisticDetector()
        self.d4_markov = MarkovNgramModelDetector()

    def scan_prompt(self, prompt: str) -> List[DetectedSpan]:
        all_spans: List[DetectedSpan] = []
        # Pass the whole prompt to each of the 4 detectors
        all_spans.extend(self.d1_regex.detect(prompt))
        all_spans.extend(self.d2_entropy.detect(prompt))
        all_spans.extend(self.d3_crf.detect(prompt))
        all_spans.extend(self.d4_markov.detect(prompt))

        # Merge and deduplicate overlapping spans
        merged = merge_spans(all_spans)
        return merged

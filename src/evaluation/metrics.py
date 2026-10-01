from typing import Dict, List, Set, Any, Union


def _normalize_tech_ids(techs) -> Set[str]:
    result = set()
    for t in techs:
        if isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id")
            if tid:
                result.add(tid.strip().upper())
        elif isinstance(t, str):
            result.add(t.strip().upper())
    return result


def _empty_grounding_result(case_id: str = "unknown") -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "total_claims": 0,
        "grounded_claims": 0,
        "weak_claims": 0,
        "unsupported_claims": 0,
        "grounding_score": 0.0,
        "citation_validity_rate": 0.0,
        "total_citations": 0,
        "valid_citations": 0,
        "flagged_claims": [],
    }


def compute_grounding_metrics(verified_data: Dict[str, Any]) -> Dict[str, Any]:
    if "claims" in verified_data and isinstance(verified_data["claims"], list):
        claims = verified_data["claims"]
        total = len(claims)
        if total == 0:
            return _empty_grounding_result(verified_data.get("case_id", "sample_verification"))

        grounded = mismatched = unsupported = 0
        flagged: List[str] = []

        for c in claims:
            v = c.get("verdict", "").upper()
            if v == "GROUNDED":
                grounded += 1
            elif v == "MISMATCHED":
                mismatched += 1
                flagged.append(c.get("claim", ""))
            else:
                unsupported += 1
                flagged.append(c.get("claim", ""))

        valid = grounded + mismatched
        score = verified_data.get("overall_grounding_score", round(grounded / total, 3))
        return {
            "case_id": verified_data.get("case_id", "sample_verification"),
            "total_claims": total,
            "grounded_claims": grounded,
            "weak_claims": mismatched,
            "unsupported_claims": unsupported,
            "grounding_score": score,
            "total_citations": total,
            "valid_citations": valid,
            "citation_validity_rate": round(valid / total, 3),
            "flagged_claims": flagged,
        }

    stages = verified_data.get("stages", [])
    total = len(stages)
    if total == 0:
        return _empty_grounding_result(verified_data.get("case_id", "unknown"))

    grounded = weak = unsupported = 0
    flagged: List[str] = []
    total_citations = valid_citations = 0

    for s in stages:
        status = s.get("status") or ("grounded" if s.get("grounded", False) else "unsupported")

        if status == "grounded":
            grounded += 1
        elif status == "weak":
            weak += 1
            flagged.append(s.get("claim", ""))
        else:
            unsupported += 1
            flagged.append(s.get("claim", ""))

        cited = s.get("artifact_ids", [])
        missing = set(s.get("missing_ids", []))
        total_citations += len(cited)
        valid_citations += sum(1 for aid in cited if aid not in missing)

    return {
        "case_id": verified_data.get("case_id", "unknown"),
        "total_claims": total,
        "grounded_claims": grounded,
        "weak_claims": weak,
        "unsupported_claims": unsupported,
        "grounding_score": round(grounded / total, 3),
        "total_citations": total_citations,
        "valid_citations": valid_citations,
        "citation_validity_rate": round(valid_citations / total_citations, 3) if total_citations else 0.0,
        "flagged_claims": flagged,
    }


def compute_mitre_metrics(
    detected_techniques: Union[List[Dict[str, Any]], Set[str], List[str]],
    ground_truth_techniques: Union[List[Dict[str, Any]], Set[str], List[str]],
) -> Dict[str, Any]:
    detected_set = _normalize_tech_ids(detected_techniques)
    truth_set = _normalize_tech_ids(ground_truth_techniques)

    tp_set = detected_set & truth_set
    fp_set = detected_set - truth_set
    fn_set = truth_set - detected_set

    tp, fp, fn = len(tp_set), len(fp_set), len(fn_set)

    precision = round(tp / (tp + fp), 3) if (tp + fp) else 0.0
    recall    = round(tp / (tp + fn), 3) if (tp + fn) else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) else 0.0

    all_techs = sorted(detected_set | truth_set)
    comparison_table = [
        {
            "technique_id": tid,
            "detected": tid in detected_set,
            "expected": tid in truth_set,
            "status": (
                "True Positive (Correct)" if tid in tp_set
                else "False Positive (Spurious)" if tid in fp_set
                else "False Negative (Missed)"
            ),
        }
        for tid in all_techs
    ]

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "detected_techniques": sorted(detected_set),
        "expected_techniques": sorted(truth_set),
        "tp_techniques": sorted(tp_set),
        "fp_techniques": sorted(fp_set),
        "fn_techniques": sorted(fn_set),
        "comparison_table": comparison_table,
    }


def _build_case_entry(
    case_name: str,
    description: str,
    is_fabricated: bool,
    plain_model_invented: bool,
    verifier_caught: bool,
    grounded_score: float,
    grounded_verdict: str,
    flagged: List[str],
) -> Dict[str, Any]:
    return {
        "case": case_name,
        "description": description,
        "is_fabricated": is_fabricated,
        "plain_model_invented": plain_model_invented,
        "verifier_caught": verifier_caught,
        "grounded_score": grounded_score,
        "grounded_verdict": grounded_verdict or ("FLAGGED" if verifier_caught else "GROUNDED"),
        "flagged_claims_count": len(flagged),
        "flagged_claims": flagged,
    }


def compute_adversarial_metrics(
    adversarial_input: Union[Dict[str, Any], List[Dict[str, Any]]]
) -> Dict[str, Any]:
    if isinstance(adversarial_input, dict) and "comparison" in adversarial_input:
        comp = adversarial_input["comparison"]
        total = adversarial_input.get("total_cases", len(comp))
        fab_total = adversarial_input.get(
            "fabricated_cases", sum(1 for c in comp if c.get("is_fabricated"))
        )
        caught = adversarial_input.get("fabricated_cases_caught_by_grounded_pipeline", 0)

        cases = [
            _build_case_entry(
                case_name=c.get("case_id", ""),
                description=c.get("description", ""),
                is_fabricated=c.get("is_fabricated", True),
                plain_model_invented=c.get("unguarded_result") == "ACCEPTED" and bool(c.get("is_fabricated")),
                verifier_caught=c.get("grounding_layer_caught_it") is True,
                grounded_score=c.get("grounded_score", 0.0),
                grounded_verdict=c.get("grounded_verdict", ""),
                flagged=[c.get("description", "")] if c.get("grounding_layer_caught_it") is True else [],
            )
            for c in comp
        ]

        return {
            "total_cases": total,
            "fabricated_cases": fab_total,
            "verifier_catch_count": caught,
            "verifier_catch_rate": round(caught / fab_total, 3) if fab_total else 0.0,
            "mean_grounded_score": adversarial_input.get("overall_grounding_score_on_case_set", 0.0),
            "cases": cases,
        }

    cases_list: List[Dict[str, Any]] = adversarial_input if isinstance(adversarial_input, list) else []
    total = len(cases_list)
    if total == 0:
        return {
            "total_cases": 0, "fabricated_cases": 0, "verifier_catch_count": 0,
            "verifier_catch_rate": 0.0, "mean_grounded_score": 0.0, "cases": [],
        }

    caught = 0
    score_sum = 0.0
    cases = []

    for res in cases_list:
        g_score = res.get("grounded_score", 0.0)
        score_sum += g_score
        flagged: List[str] = res.get("grounded_flagged_claims", [])
        was_caught: bool = res.get("grounded_caught_something", len(flagged) > 0)
        if was_caught:
            caught += 1

        cases.append(
            _build_case_entry(
                case_name=res.get("case", "unknown"),
                description=res.get("description", ""),
                is_fabricated=res.get("is_fabricated", True),
                plain_model_invented=res.get("plain_model_invented", True),
                verifier_caught=was_caught,
                grounded_score=g_score,
                grounded_verdict="",
                flagged=flagged,
            )
        )

    return {
        "total_cases": total,
        "fabricated_cases": total,
        "verifier_catch_count": caught,
        "verifier_catch_rate": round(caught / total, 3),
        "mean_grounded_score": round(score_sum / total, 3),
        "cases": cases,
    }

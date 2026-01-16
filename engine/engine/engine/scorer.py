TIER_WEIGHT = {"Tier-1": 100, "Tier-2": 70, "Tier-3": 40}

def score_path(path, tier):
    base = TIER_WEIGHT.get(tier, 10)
    penalty = len(path) * 7
    score = base - penalty
    return max(min(score, 100), 0)

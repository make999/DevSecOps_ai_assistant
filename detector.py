import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np

def load_logs(path: str, log_type: str = "ssh") -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    if log_type == "ssh":
        return df[["timestamp","src_ip","user","event","status","port"]]
    elif log_type == "firewall":
        return df[["timestamp","src_ip","dst_ip","port","action"]]
    else:
        return df

def sliding_window_features(df: pd.DataFrame, window_minutes: int = 5) -> pd.DataFrame:
    window_minutes = int(max(1, window_minutes))
    dfa = df[df["event"] == "auth"].copy()
    dfa["timestamp"] = pd.to_datetime(dfa["timestamp"], utc=True)

    per_min = (
        dfa.groupby(["src_ip", pd.Grouper(key="timestamp", freq="1min")])
           .agg(
               total=("status", "size"),
               fails=("status", lambda s: (s == "fail").sum()),
               successes=("status", lambda s: (s == "success").sum()),
               users=("user", "nunique"),
               ports=("port", "nunique"),     
           )
           .reset_index()
           .sort_values(["src_ip","timestamp"])
           .reset_index(drop=True)
    )

    cols = ["total","fails","successes","users","ports"] 
    for col in cols:
        per_min[f"r{window_minutes}m_{col}"] = (
            per_min.groupby("src_ip")[col]
                   .rolling(window=window_minutes, min_periods=1)
                   .sum()
                   .reset_index(level=0, drop=True)
        )

    per_min["fail_rate"] = (
        per_min[f"r{window_minutes}m_fails"] / per_min[f"r{window_minutes}m_total"].clip(lower=1)
    )
    per_min["avg_interval_sec"] = (window_minutes * 60) / per_min[f"r{window_minutes}m_total"].clip(lower=1)  # NEW
    per_min["minute"] = per_min["timestamp"].dt.floor("1min") 

    return per_min.fillna(0.0)

def rule_based_flags(features: pd.DataFrame, fail_threshold:int=10, window_minutes:int=5) -> pd.DataFrame:
    flags = features.copy()
    flags["rule_bruteforce"] = flags[f"r{window_minutes}m_fails"] >= fail_threshold
    flags["is_suspicious_rule"] = flags["rule_bruteforce"]
    return flags

def isolation_forest_scores(features: pd.DataFrame, contamination: float = 0.02) -> pd.DataFrame:
    cols = [c for c in features.columns if c.startswith("r") or c in ["fail_rate","avg_interval_sec"]]
    X = features[cols].astype(float).fillna(0.0)
    if len(X) < 10:
        features = features.copy()
        features["if_score"] = 0.0
        features["is_suspicious_if"] = False
        return features
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X)
    scores = -model.score_samples(X) 
    features = features.copy()
    features["if_score"] = scores
    thresh = pd.Series(scores).quantile(1 - contamination)
    features["is_suspicious_if"] = features["if_score"] >= thresh
    return features

def merge_findings(flags: pd.DataFrame) -> pd.DataFrame:
    out = flags.copy()
    out["is_suspicious"] = out["is_suspicious_rule"] | out["is_suspicious_if"]
    return out

def _normalize(series: pd.Series) -> pd.Series:
    if series.empty:
        return series
    mn, mx = float(series.min()), float(series.max())
    if mx - mn < 1e-9:
        return pd.Series(0.0, index=series.index)
    return (series - mn) / (mx - mn)

def summarize_incidents(findings: pd.DataFrame, top_k:int=20) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["src_ip","last_seen","max_if_score","rule_hits","total_minutes","risk","severity"])
    agg = (findings.groupby("src_ip")
                    .agg(last_seen=("timestamp","max"),
                         max_if_score=("if_score","max"),
                         rule_hits=("is_suspicious_rule","sum"),
                         total_minutes=("timestamp","size"))
                    .reset_index())
    norm_if = _normalize(agg["max_if_score"].fillna(0.0))
    agg["risk"] = 2.0*agg["rule_hits"].astype(float) + 10.0*norm_if
    agg["severity"] = pd.cut(
        agg["risk"],
        bins=[-1, 5, 20, float("inf")], 
        labels=["Low", "Medium", "High"]
    )
    return agg.sort_values(["risk","last_seen"], ascending=[False, False]).head(top_k)

def summarize_firewall_incidents(logs_fw: pd.DataFrame, top_k:int=20) -> pd.DataFrame:
    blocked = logs_fw[logs_fw["action"].astype(str).str.lower() == "deny"].copy()
    if blocked.empty:
        return pd.DataFrame(columns=["src_ip","denies","last_seen"])
    agg = (blocked.groupby("src_ip").agg(denies=("src_ip","size"),last_seen=("timestamp","max")).reset_index())
    agg["severity"] = pd.qcut(agg["denies"].rank(method="first"), q=3, labels=["Low","Medium","High"])
    agg["risk"] = agg["denies"].astype(float)
    return agg.sort_values(["denies","last_seen"], ascending=[False, False]).head(top_k)

def run_detection(csv_path: str,
                  window_minutes:int=5,
                  fail_threshold:int=10,
                  contamination:float=0.02,
                  log_type: str = "ssh"):
    logs = load_logs(csv_path, log_type=log_type)

    if log_type == "ssh":
        feats = sliding_window_features(logs, window_minutes=window_minutes)
        flagged = rule_based_flags(feats, fail_threshold=fail_threshold, window_minutes=window_minutes)
        with_if = isolation_forest_scores(flagged, contamination=contamination)
        merged = merge_findings(with_if)
        incidents = summarize_incidents(merged, top_k=50)
        return logs, merged, incidents

    elif log_type == "firewall":
        incidents = summarize_firewall_incidents(logs, top_k=50)
        findings = pd.DataFrame()
        return logs, findings, incidents

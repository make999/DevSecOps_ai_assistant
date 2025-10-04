import pandas as pd
import numpy as np

def build_series(findings: pd.DataFrame, window_minutes: int = 5) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["minute","fails_per_min","anomalies"])
    df = findings.copy()
    if "minute" not in df.columns:
        df["minute"] = df["timestamp"].dt.floor("1min")
    out = (df.groupby("minute")["fails"].sum().reset_index())
    out.rename(columns={"fails":"fails_per_min"}, inplace=True)
    if "is_suspicious" in df.columns:
        an = (df.groupby("minute")["is_suspicious"].sum().reset_index())
        out = out.merge(an, on="minute", how="left")
        out.rename(columns={"is_suspicious":"anomalies"}, inplace=True)
    else:
        out["anomalies"] = 0
    return out

def simple_linear_forecast(series_df: pd.DataFrame, horizon_minutes: int = 60) -> pd.DataFrame:
    if series_df.empty or len(series_df) < 3:
        return pd.DataFrame(columns=["minute","forecast"])
    s = series_df.dropna().reset_index(drop=True)
    y = s["fails_per_min"].astype(float).values
    x = np.arange(len(y))
    coef = np.polyfit(x, y, 1)
    trend = np.poly1d(coef)
    x_future = np.arange(len(y), len(y) + horizon_minutes)
    y_future = trend(x_future).clip(min=0.0)
    future_index = s["minute"].iloc[-1] + pd.to_timedelta(np.arange(1, horizon_minutes+1), unit="min")
    return pd.DataFrame({"minute": future_index, "forecast": y_future})

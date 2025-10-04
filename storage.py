import os, json
import pandas as pd

BLOCKLIST_PATH = os.environ.get("BLOCKLIST_PATH", "blocklist.json")

def load_blocklist():
    if os.path.exists(BLOCKLIST_PATH):
        with open(BLOCKLIST_PATH, "r") as f:
            return set(json.load(f))
    return set()

def save_blocklist(blocked_ips):
    with open(BLOCKLIST_PATH, "w") as f:
        json.dump(sorted(list(blocked_ips)), f)

def block_ip(ip: str):
    ips = load_blocklist()
    ips.add(ip)
    save_blocklist(list(ips))


def unblock_ip(ip: str):
    bl = load_blocklist()
    bl = [x for x in bl if x != ip]
    save_blocklist(bl)


def filter_by_time(df: pd.DataFrame, start, end):
    mask = (df["timestamp"] >= start) & (df["timestamp"] <= end)
    return df.loc[mask].copy()

import os
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from detector import run_detection
from chat import intent_to_filter, intent_to_query
from storage import load_blocklist, block_ip, filter_by_time, unblock_ip
from forecast import build_series, simple_linear_forecast
import altair as alt
from pathlib import Path
import json
import csv


st.set_page_config(page_title="Agai - DevSecOps AI Assistant", layout="wide")
st.title("Agai - DevSecOps AI Assistant")
st.sidebar.title("Log Source")
log_source = st.sidebar.selectbox(
    "Choose log source",
    ["SSH Logs (sample_logs.csv)", "Firewall Logs (firewall_logs.csv)", "Cowrie Honeypot Logs (cowrie_logs.csv)", "Threat Intel Logs (threat_logs.csv)",]
)

if log_source.startswith("SSH"):
    DATA_PATH = "data/sample_logs.csv"
    log_type = "ssh"
elif log_source.startswith("Firewall"):
    DATA_PATH = "data/firewall_logs.csv"
    log_type = "firewall"
elif log_source.startswith("Cowrie"):
    DATA_PATH = "data/cowrie_logs.csv"
    log_type = "cowrie"
elif log_source.startswith("Threat"):
    DATA_PATH = "data/threat_logs.csv"
    log_type = "threat"


st.sidebar.write("CSV logs path:", DATA_PATH)
window_minutes = st.sidebar.slider("Rolling window (minutes)", 1, 15, 5)
fail_threshold = st.sidebar.slider("Fail threshold (rule)", 3, 50, 10)
contamination = st.sidebar.slider("IF contamination", 0.01, 0.2, 0.02, step=0.01)

st.sidebar.markdown("---")
st.sidebar.write("**Blocklist**")
blocked = sorted(load_blocklist())
if blocked:
    st.sidebar.code("\n".join(blocked))
    ip_to_unblock = st.sidebar.selectbox("Unblock IP", [""] + blocked)
    if st.sidebar.button("✅ Unblock IP"):
        if ip_to_unblock:
            unblock_ip(ip_to_unblock)
            st.sidebar.success(f"IP {ip_to_unblock} removed from blocklist. Refresh to update.")
else:
    st.sidebar.code("(empty)")

def sync_cowrie_to_csv():
    cowrie_json = Path("cowrie_logs/log/cowrie/cowrie.json")
    out_csv = Path("data/cowrie_logs.csv")
    fields = ["timestamp", "src_ip", "dst_port", "eventid", "username", "password"]

    if not cowrie_json.exists():
        return

    if not out_csv.exists():
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()

    with cowrie_json.open("r", encoding="utf-8") as f, \
         out_csv.open("w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=fields)
        writer.writeheader()
        for line in f:
            try:
                ev = json.loads(line)
                writer.writerow({
                    "timestamp": ev.get("timestamp"),
                    "src_ip": ev.get("src_ip"),
                    "dst_port": ev.get("dst_port"),
                    "eventid": ev.get("eventid"),
                    "username": ev.get("username"),
                    "password": ev.get("password"),
                })
            except Exception:
                continue

sync_cowrie_to_csv()
if log_type == "cowrie":
    logs = pd.read_csv("data/cowrie_logs.csv")
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
    findings = pd.DataFrame()
    incidents = (logs.groupby("src_ip")
                      .size()
                      .reset_index(name="events")
                      .sort_values("events", ascending=False)
                      .head(50))
else:
    logs, findings, incidents = run_detection(
        DATA_PATH, window_minutes, fail_threshold, contamination, log_type=log_type
    )


incidents_view = incidents[~incidents["src_ip"].isin(blocked)].copy()
if "severity" in incidents_view.columns:
    high_risk_ips = incidents_view[incidents_view["severity"] == "High"]["src_ip"].unique()
    for ip in high_risk_ips:
        block_ip(ip)
tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "💬 Chat", "⚙️ Incidents"])

with tab1:
    if log_type == "ssh":
        col1, col2 = st.columns([2,1], gap="large")
        with col1:
            sev_order = {"High": 3, "Medium": 2, "Low": 1}
            tbl = incidents_view.copy()
            if "severity" not in tbl.columns: tbl["severity"] = "Low"
            if "risk" not in tbl.columns: tbl["risk"] = 0.0

            tbl["sev_rank"] = tbl["severity"].map(lambda x: sev_order.get(str(x), 0)).astype(int)
            tbl["severity_badge"] = tbl["severity"].map({
                "High": "🔴 High", "Medium": "🟠 Medium", "Low": "🟢 Low"
            }).fillna("🟢 Low")

            tbl_sorted = tbl.sort_values(["sev_rank", "risk"], ascending=[False, False])
            if not tbl_sorted.empty:
                top_row = tbl_sorted.iloc[0]
                st.metric(
                    "Highest risk IP",
                    value=str(top_row["src_ip"]),
                    help=f"Risk={top_row['risk']:.2f} | Severity={top_row['severity']} | Rule hits={int(top_row.get('rule_hits',0))}"
                )

            cols_show = ["src_ip", "risk", "severity_badge", "last_seen", "rule_hits", "max_if_score", "total_minutes"]
            cols_show = [c for c in cols_show if c in tbl_sorted.columns]
            st.dataframe(
                tbl_sorted[cols_show].rename(columns={"severity_badge": "severity"}),
                use_container_width=True
            )

            st.markdown("**Anomaly timeline (fails/min & anomalies)**")
            if not findings.empty:
                series_df = build_series(findings, window_minutes).sort_values("minute")
                line = (
                    alt.Chart(series_df)
                    .mark_line()
                    .encode(
                        x=alt.X("minute:T", axis=alt.Axis(title="Time (UTC)", format="%H:%M", labelAngle=-45, tickCount=10)),
                        y=alt.Y("fails_per_min:Q", title="Fails / min"),
                        tooltip=[alt.Tooltip("minute:T", format="%Y-%m-%d %H:%M"), "fails_per_min:Q"]
                    )
                    .properties(height=200, width="container")
                )
                st.altair_chart(line, use_container_width=True)

                bars = (
                    alt.Chart(series_df)
                    .mark_bar()
                    .encode(
                        x=alt.X("minute:T", axis=alt.Axis(title="Time (UTC)", format="%H:%M", labelAngle=-45, tickCount=10)),
                        y=alt.Y("anomalies:Q", title="Anomalies"),
                        tooltip=[alt.Tooltip("minute:T", format="%Y-%m-%d %H:%M"), "anomalies:Q"]
                    )
                    .properties(height=160, width="container")
                )
                st.altair_chart(bars, use_container_width=True)
            else:
                st.info("No minute-level data for visualization.")

            st.markdown("**Forecast (next 60 min)**")
            if not findings.empty:
                fdf = simple_linear_forecast(build_series(findings, window_minutes), horizon_minutes=60)
                if not fdf.empty:
                    forecast_chart = (
                        alt.Chart(fdf.sort_values("minute"))
                        .mark_line()
                        .encode(
                            x=alt.X("minute:T", axis=alt.Axis(title="Time (UTC)", format="%H:%M", labelAngle=-45, tickCount=10)),
                            y=alt.Y("forecast:Q", title="Forecast (fails/min)"),
                            tooltip=[alt.Tooltip("minute:T", format="%Y-%m-%d %H:%M"), "forecast:Q"]
                        )
                        .properties(height=160, width="container")
                    )
                    st.altair_chart(forecast_chart, use_container_width=True)
                else:
                    st.caption("Data not enough for forecast.")
        with col2:
            st.subheader("Actions")
            ip_to_block = st.selectbox("Block IP", [""] + incidents_view["src_ip"].astype(str).tolist())
            if st.button("🚫 Block IP"):
                if ip_to_block:
                    block_ip(ip_to_block)
                    st.success(f"IP {ip_to_block} added to blocklist (simulation). Refresh to update views.")
            st.caption("Blocking is simulated: the IP disappears from tables but no real firewall changes are made.")

            fw_path = "data/firewall_logs.csv"
            if os.path.exists(fw_path):
                try:
                    fw = pd.read_csv(fw_path)
                    fw["timestamp"] = pd.to_datetime(fw["timestamp"], utc=True)
                    fw_denies = fw[fw["action"].astype(str).str.lower() == "deny"]
                    fw_counts = fw_denies.groupby("src_ip").size().reset_index(name="fw_denies")
                    corr = incidents_view.merge(fw_counts, on="src_ip", how="left").fillna({"fw_denies":0})
                    corr["corr_boosted_severity"] = corr.apply(
                        lambda r: "High" if (r.get("severity","Low") in ["Medium","High"] and r["fw_denies"]>0) else r.get("severity","Low"),
                        axis=1
                    )
                    st.subheader("Cross-source correlation (SSH × Firewall)")
                    st.dataframe(corr[["src_ip","risk","severity","fw_denies","corr_boosted_severity"]], use_container_width=True)
                except Exception as e:
                    st.caption(f"Correlation skipped: {e}")
    elif log_type == "firewall":
        st.subheader("Firewall Events Overview")
        st.dataframe(logs.head(50), use_container_width=True)

        blocked = logs[logs.get("action","").astype(str).str.lower() == "deny"]
        if not blocked.empty:
            top_blocked = blocked["src_ip"].value_counts().head(5).reset_index()
            top_blocked.columns = ["src_ip","denies"]
            st.write("Top IP by blocking:")
            st.bar_chart(top_blocked.set_index("src_ip"))
        else:
            st.info("No deny-events in current file.")
    elif log_type == "cowrie":
        st.subheader("Cowrie Honeypot Overview")
        st.dataframe(logs.head(50), use_container_width=True)

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("**Top source IPs**")
            top_ips = logs["src_ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["src_ip","events"]
            st.dataframe(top_ips, use_container_width=True)
        with col_b:
            st.markdown("**Top usernames**")
            if "username" in logs.columns:
                top_users = logs["username"].dropna().astype(str).value_counts().head(10).reset_index()
                top_users.columns = ["username","events"]
                st.dataframe(top_users, use_container_width=True)
            else:
                st.caption("No username column")
        with col_c:
            st.markdown("**Top passwords**")
            if "password" in logs.columns:
                top_pw = logs["password"].dropna().astype(str).value_counts().head(10).reset_index()
                top_pw.columns = ["password","events"]
                st.dataframe(top_pw, use_container_width=True)
            else:
                st.caption("No password column")

    elif log_type == "threat":
        st.subheader("Threat Intelligence Overview")
        st.dataframe(logs.head(50), use_container_width=True)

        top_malware = logs["malware"].value_counts().head(10).reset_index()
        top_malware.columns = ["malware","count"]
        st.markdown("**Top Malware Families**")
        st.bar_chart(top_malware.set_index("malware"))

        top_ips = logs["src_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["src_ip","count"]
        st.markdown("**Top Command & Control IPs**")
        st.dataframe(top_ips, use_container_width=True)

with tab2:
    st.subheader("Ask in natural language")

    if log_type == "ssh":
        user_q = st.text_input(
            "For example: 'most frequent user who unsuccessfully logged in in an hour' / 'top 5 IPs with unsuccessful logins in 5 minutes' / 'how many unsuccessful logins per day'"
        )
        if st.button("Ask", key="ask_ssh"):
            if not user_q.strip():
                st.warning("Your query.")
            else:
                from chat import intent_to_query  
                intent = intent_to_query(user_q, log_type="ssh")  # Gemini-first
                st.write("Parsed intent:", {
                    "start": intent["start"].isoformat(),
                    "end": intent["end"].isoformat(),
                    "event": intent.get("event"),
                    "status": intent.get("status"),
                    "op": intent["op"],
                    "limit": intent["limit"],
                    "target": intent.get("target"),
                    "context": intent.get("context"),
                })

                logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
                sub = logs[(logs["timestamp"] >= intent["start"]) & (logs["timestamp"] <= intent["end"])].copy()

                if intent.get("event") and "event" in sub.columns:
                    sub = sub[sub["event"] == intent["event"]]
                if intent.get("status") and "status" in sub.columns:
                    sub = sub[sub["status"] == intent["status"]]

                if sub.empty:
                    sub = logs[(logs["timestamp"] >= intent["end"] - pd.Timedelta(days=1)) & (logs["timestamp"] <= intent["end"])].copy()
                    if intent.get("event") and "event" in sub.columns:
                        sub = sub[sub["event"] == intent["event"]]
                    if intent.get("status") and "status" in sub.columns:
                        sub = sub[sub["status"] == intent["status"]]
                    st.caption("Nothing found for the selected period. Data for the last 24 hours is shown.")
                
                if intent["op"] == "block_ip" and intent.get("target"):
                    block_ip(str(intent["target"]))
                    st.success(f"IP {intent['target']} added to blocklist.")
                    st.stop()

                if intent["op"] == "unblock_ip" and intent.get("target"):
                    unblock_ip(str(intent["target"]))
                    st.success(f"IP {intent['target']} removed from blocklist.")
                    st.stop()
                op = intent["op"]; limit = intent["limit"]
                if sub.empty:
                    st.info("There are no events matching your request.")
                else:
                    if op == "top_users":
                        ans = (sub.groupby("user").size().reset_index(name="events")
                               .sort_values("events", ascending=False).head(limit))
                        st.write(f"Top {len(ans)} users:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "top_ips":
                        ans = (sub.groupby("src_ip").size().reset_index(name="events")
                               .sort_values("events", ascending=False).head(limit))
                        st.write(f"Top {len(ans)} IP-addresses:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "count":
                        st.write(f"Number of events: **{len(sub)}**")
                    else:
                        st.write(f"{len(sub)} events found (first 200):")
                        st.dataframe(sub.head(200), use_container_width=True)

    elif log_type == "firewall":
        user_q_fw = st.text_input(
            "Firewall: for example, 'top 10 IPs by deny per day' / 'how many deny in 5 minutes' / 'show deny in an hour'"
        )
        if st.button("Ask", key="ask_fw"):
            if not user_q_fw.strip():
                st.warning("Введите запрос.")
            else:
                intent = intent_to_query(user_q_fw, log_type="firewall")
            st.write("Parsed intent:", {
                "start": intent["start"].isoformat(),
                "end": intent["end"].isoformat(),
                "op": intent["op"],
                "limit": intent["limit"],
                "action": intent.get("action"),
                "target": intent.get("target"),
            })

            if intent["op"] == "block_ip" and intent.get("target"):
                block_ip(str(intent["target"]))
                st.success(f"IP {intent['target']} added to blocklist.")
                st.stop()
            if intent["op"] == "unblock_ip" and intent.get("target"):
                from storage import unblock_ip
                unblock_ip(str(intent["target"]))
                st.success(f"IP {intent['target']} deleted from blocklist.")
                st.stop()

            logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
            sub = logs[(logs["timestamp"] >= intent["start"]) & (logs["timestamp"] <= intent["end"])].copy()

            action = intent.get("action")
            if action and "action" in sub.columns:
                sub = sub[sub["action"].astype(str).str.lower() == action.lower()]

            if sub.empty:
                st.info("There are no events matching your request.")
            else:
                op, limit = intent["op"], intent["limit"]
                if op == "top_ips":
                    ans = (sub.groupby("src_ip").size().reset_index(name="events")
                           .sort_values("events", ascending=False).head(limit))
                    st.write(f"Топ {len(ans)} IP (filter action: {action or '—'}):")
                    st.dataframe(ans, use_container_width=True)
                elif op == "count":
                    st.write(f"Events count: **{len(sub)}**")
                else:
                    st.write(f"{len(sub)} events found (first 200):")
                    st.dataframe(sub.head(200), use_container_width=True)
    elif log_type == "cowrie":
        user_q_cw = st.text_input(
            "Cowrie: for example, 'top 10 IPs for the hour' / 'most common passwords for the day' / 'top users for 5 minutes'"
        )
        if st.button("Ask", key="ask_cowrie"):
            if not user_q_cw.strip():
                st.warning("Enter your request.")
            else:
                intent = intent_to_query(user_q_cw, log_type="cowrie")  # Gemini -> fallback
                st.write("Parsed intent:", {
                    "start": intent["start"].isoformat(),
                    "end": intent["end"].isoformat(),
                    "event": intent.get("event"),
                    "status": intent.get("status"),
                    "op": intent["op"],
                    "limit": intent["limit"],
                    "target": intent.get("target"),
                    "context": intent.get("context"),
                })

                logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
                sub = logs[(logs["timestamp"] >= intent["start"]) & (logs["timestamp"] <= intent["end"])].copy()

                if intent.get("eventid") and "eventid" in sub.columns:
                    sub = sub[sub["eventid"].astype(str).str.contains(intent["eventid"], case=False, na=False)]
                if intent.get("username") and "username" in sub.columns:
                    sub = sub[sub["username"].astype(str).str.contains(intent["username"], case=False, na=False)]
                if intent.get("password") and "password" in sub.columns:
                    sub = sub[sub["password"].astype(str).str.contains(intent["password"], case=False, na=False)]

                if sub.empty:
                    st.info("There are no events matching your request.")
                else:
                    op, limit = intent["op"], intent["limit"]
                    if op == "top_ips":
                        ans = sub["src_ip"].value_counts().head(limit).reset_index()
                        ans.columns = ["src_ip","events"]
                        st.dataframe(ans, use_container_width=True)
                    elif op == "top_users" and "username" in sub.columns:
                        ans = sub["username"].astype(str).value_counts().head(limit).reset_index()
                        ans.columns = ["username","events"]
                        st.dataframe(ans, use_container_width=True)
                    elif op == "top_passwords" and "password" in sub.columns:
                        ans = sub["password"].astype(str).value_counts().head(limit).reset_index()
                        ans.columns = ["password","events"]
                        st.dataframe(ans, use_container_width=True)
                    elif op == "count":
                        st.write(f"Events count: **{len(sub)}**")
                    else:
                        st.dataframe(sub.head(200), use_container_width=True)
    elif log_type == "threat":
        user_q_threat = st.text_input(
            "Threat Intel: e.g. 'top 10 malware families today' / 'show C2 IPs with cobalt strike' / 'how many threats with asyncrat'"
        )
        if st.button("Ask", key="ask_threat"):
            if not user_q_threat.strip():
                st.warning("Enter your request.")
            else:
                intent = intent_to_query(user_q_threat, log_type="threat")
                st.write("Parsed intent:", {
                    "start": intent["start"].isoformat(),
                    "end": intent["end"].isoformat(),
                    "op": intent["op"],
                    "limit": intent["limit"],
                    "event": intent.get("event"),
                    "target": intent.get("target"),
                    "context": intent.get("context"),
                })

                # threat_logs.csv не содержит timestamp — пропускаем фильтрацию по времени
                sub = logs.copy()

                # filter by malware / ip (если указано)
                if intent.get("target") and "src_ip" in sub.columns:
                    sub = sub[sub["src_ip"].astype(str).str.contains(intent["target"], case=False, na=False)]
                if intent.get("event") and "malware" in sub.columns:
                    sub = sub[sub["malware"].astype(str).str.contains(intent["event"], case=False, na=False)]

                if sub.empty:
                    st.info("No matching threats found.")
                else:
                    op, limit = intent["op"], intent["limit"]
                    if op == "top_ips" and "src_ip" in sub.columns:
                        ans = sub["src_ip"].value_counts().head(limit).reset_index()
                        ans.columns = ["src_ip","detections"]
                        st.write(f"Top {len(ans)} threat IPs:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "top_users" or op == "top_malware" or "malware" in sub.columns:
                        ans = sub["malware"].value_counts().head(limit).reset_index()
                        ans.columns = ["malware","detections"]
                        st.write(f"Top {len(ans)} malware families:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "count":
                        st.write(f"Threat entries count: **{len(sub)}**")
                    else:
                        st.write(f"{len(sub)} threat entries (first 200):")
                        st.dataframe(sub.head(200), use_container_width=True)

with tab3:
    if log_type == "ssh":
        st.subheader("Minute-level findings")
        st.dataframe(findings.head(500), use_container_width=True)
    elif log_type == "firewall":
        st.subheader("Firewall incidents (top denied sources)")
        st.dataframe(incidents.head(50), use_container_width=True)
    elif log_type == "cowrie":
        st.subheader("Cowrie summary (top sources)")
        st.dataframe(incidents.head(50), use_container_width=True)
    elif log_type == "threat":  # new
        st.subheader("Threat Intelligence Summary (Top Malware & C2 IPs)")
        st.dataframe(incidents.head(50), use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Top Malware Families**")
            top_mal = (
                logs["malware"].value_counts()
                .reset_index()
                .rename(columns={"index": "malware", "malware": "detections"})
                .head(10)
            )
            st.dataframe(top_mal, use_container_width=True)

        with col2:
            st.markdown("**Top C2 IP Addresses**")
            top_ips = (
                logs["src_ip"].value_counts()
                .reset_index()
                .rename(columns={"index": "src_ip", "src_ip": "detections"})
                .head(10)
            )
            st.dataframe(top_ips, use_container_width=True)



st.markdown("---")
st.caption("MVP demo: rules + Isolation Forest for anomalies, simple NL parsing instead of a full LLM. Replace 'intent_to_filter' with an LLM call for production.")

import os, re, json
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv()

import google.generativeai as genai

_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")


def _first_scalar(x):
    if isinstance(x, list):
        return _first_scalar(x[0]) if x else None
    if isinstance(x, dict):
        for k in ("value", "text", "name"):
            if k in x:
                return _first_scalar(x[k])
        if x:
            return _first_scalar(next(iter(x.values())))
        return None
    return x

def _to_str_or_none(x):
    x = _first_scalar(x)
    return str(x) if x is not None else None

def _to_int_or(default, lo=1, hi=1000):
    def conv(x):
        x = _first_scalar(x)
        try:
            n = int(x)
            return max(lo, min(hi, n))
        except Exception:
            return default
    return conv

def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _coerce_datetime(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def debug_intent(query: str="block IP 123.45.67.89 for today", log_type: str="ssh"):
    try:
        parsed = intent_to_filter(query, log_type)
        print("\n[DEBUG Gemini] RAW:", query)
        print("[DEBUG Gemini] RESULT:", parsed)
        return parsed
    except Exception as e:
        print(f"[DEBUG Gemini] FAILED ({e}), fallback...")
        parsed = intent_to_query(query, log_type)
        print("[DEBUG Fallback] RESULT:", parsed)
        return parsed
def parse_time_window(text: str):
    q = text.lower()
    now = datetime.now(timezone.utc)
    if "last hour" in q or "per hour" in q:
        return now - timedelta(hours=1), now
    if "for day" in q or "today" in q:
        return now - timedelta(days=1), now
    if "last 5 minut" in q or "for 5 minut" in q or "for five minut" in q:
        return now - timedelta(minutes=5), now
    return now - timedelta(hours=1), now

def _extract_int(q: str, default: int) -> int:
    m = re.search(r"\b(\d{1,3})\b", q)
    if m:
        try:
            n = int(m.group(1))
            return max(1, min(1000, n))
        except Exception:
            pass
    return default


def intent_to_filter(query: str, log_type: str = "ssh"):
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY is not set")

    genai.configure(api_key=api_key)

    response_schema = {
        "type": "object",
        "properties": {
            "start":   {"type": "string", "format": "date-time", "nullable": True},
            "end":     {"type": "string", "format": "date-time", "nullable": True},

            "event":   {"type": "string", "enum": ["auth","firewall","cowrie"], "nullable": True},
            "status":  {"type": "string", "enum": ["fail","success"], "nullable": True},
            "action":  {"type": "string", "enum": ["deny","allow"], "nullable": True},

            "eventid": {"type": "string", "nullable": True},
            "username":{"type": "string", "nullable": True},
            "password":{"type": "string", "nullable": True},

            "op":      {"type": "string", "enum": [
                "top_ips","top_users","top_passwords","count",
                "timeline","report","block_ip","unblock_ip",
                "incident","list"
            ]},

            "limit":   {"type": "integer"},
            "context": {"type": "string", "enum": ["executive","analyst","technical"]},
            "target":  {"type": "string", "nullable": True},
        },
        "required": ["op"],
        "additionalProperties": False
    }

    generation_config = {
        "temperature": 0.2,
        "response_mime_type": "application/json",
        #"response_schema": response_schema,
    }

    system_instruction = f"""
You are a SecOps Assistant. Return STRICT JSON according to the schema. No comments.
Current UTC: "{_iso_utc(datetime.now(timezone.utc))}"
Time rules:
- "per hour" -> [now-1h, now]
- "per day" -> [now-24h, now]
- "per 5 minutes" -> [now-5m, now]
Logical rules:
- If the request is for blocking and an IP is specified -> op="block_ip"
- If for unblocking -> op="unblock_ip"
- Report/summary -> op="report"
- Incident -> op="incident"
- Top N -> op="top_ips"/"top_users"/"top_passwords"
- Number -> op="count"
- Otherwise -> op="list"
"""

    now = datetime.now(timezone.utc)

    few_shots = [
        f'Query: "Block IP 123.45.67.89 today"',
        '{ "op":"block_ip", "target":"123.45.67.89", "start":"%NOW-24H%", "end":"%NOW%", "context":"analyst" }',
        f'Query: "Unblock 123.45.67.89"',
        '{ "op":"unblock_ip", "target":"123.45.67.89", "start":"%NOW-1H%", "end":"%NOW%", "context":"analyst" }',
        f'Query: "Top 10 IPs by deny for the day"',
        '{ "op":"top_ips", "limit":10, "action":"deny", "start":"%NOW-24H%", "end":"%NOW%", "context":"analyst" }'
    ]

    def sub_time(s):
        return (s.replace("%NOW%", _iso_utc(now))
                 .replace("%NOW-1H%", _iso_utc(now - timedelta(hours=1)))
                 .replace("%NOW-24H%", _iso_utc(now - timedelta(days=1)))
                 .replace("%NOW-5M%", _iso_utc(now - timedelta(minutes=5))))

    content = [sub_time(x) for x in few_shots] + [f'Запрос: """{query}"""']

    model = genai.GenerativeModel(
        _GEMINI_MODEL,
        system_instruction=system_instruction,
        generation_config=generation_config,
    )

    resp = model.generate_content(content)

    text = (getattr(resp, "text", None) or "").strip()
    if not text:
        try:
            text = json.dumps(resp.candidates[0].content.parts[0].text)  # может не сработать, просто попытка
        except Exception:
            raise RuntimeError("Empty response from Gemini")

    try:
        def _coerce_obj(x):
            if isinstance(x, list):
                for it in x:
                    if isinstance(it, dict):
                        return it
                return {}
            if isinstance(x, dict):
                return x
            return {}
        parsed = json.loads(text)
        parsed = _coerce_obj(parsed)

    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, flags=re.S)
        if not m:
            raise
        parsed = json.loads(m.group(0))

    if "limit" not in parsed:
        parsed["limit"] = _extract_int(query.lower(), 10)
    if "context" not in parsed:
        parsed["context"] = "analyst"

    if parsed.get("op") in ("block_ip","unblock_ip") and not parsed.get("target"):
        m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
        if m:
            parsed["target"] = m.group(0)

    if isinstance(parsed.get("start"), str):
        parsed["start"] = _coerce_datetime(parsed["start"])
    else:
        parsed["start"] = now - timedelta(hours=1)
    if isinstance(parsed.get("end"), str):
        parsed["end"] = _coerce_datetime(parsed["end"])
    else:
        parsed["end"] = now

    print("[Gemini]", text, parsed)
    return parsed


def intent_to_query(query: str, log_type: str = "ssh"):
    try:
        return intent_to_filter(query, log_type=log_type)
    except Exception as e:
        print(f"[intent_to_query] Gemini failed, fallback: {e}")
        start, end = parse_time_window(query)
        q = query.lower()
        op = "list"
        limit = _extract_int(q, 10)
        if "топ" in q or "top" in q or "most freq" in q or "most common":
            if "src_ip" in q: op = "top_ips"
            elif "user" in q or "username" in q: op = "top_users"
            elif "passw" in q: op = "top_passwords"
        elif "how" in q or "count" in q:
            op = "count"

        base = {"start": start, "end": end, "op": op, "limit": limit, "context":"analyst"}
        if log_type == "ssh":
            if any(w in q for w in ["session","login","auth"]): base["event"] = "auth"
            if any(w in q for w in ["failure","fail","error"]): base["status"] = "fail"
        elif log_type == "firewall":
            if any(w in q for w in ["deny","block","blocked"]): base["action"] = "deny"
        elif log_type == "threat":
            if any(w in q for w in ["malware","botnet","threat","cobalt","rat","beacon"]): base["event"] = "threat"
        elif log_type == "cowrie":
            pass
        return base

import hashlib
from datetime import datetime


def _parse_syslog_date(date_str: str) -> datetime:
    """
    Parse a syslog timestamp of the form 'MMM DD HH:MM:SS' (no year).

    To handle the December → January year-boundary correctly we assign the
    current year by default, then subtract one year if the resulting date
    would be more than 6 months in the future (which means the log entry
    actually belongs to the previous year).
    """
    from datetime import timedelta
    now = datetime.now()
    try:
        parsed = datetime.strptime(date_str.strip(), "%b %d %H:%M:%S")
        # Inject the current year as first guess
        parsed = parsed.replace(year=now.year)
        # If the date is more than 6 months ahead, it must belong to last year
        if (parsed - now).days > 180:
            parsed = parsed.replace(year=now.year - 1)
        return parsed
    except ValueError:
        # Unparseable date: sort to the very beginning so bad entries don't hide good ones
        return datetime.min
from typing import Dict, List, Any
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

# ==========================================
# GLOBAL INITIALIZATION (Executed once only)
# ==========================================

embedding = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

vector_store = Chroma(
    persist_directory="./chroma_db/",
    collection_name="security_alerts",
    embedding_function=embedding
)

# ==========================================
# HELPERS
# ==========================================

def _flatten_ip(raw_ip: Any) -> str:
    """
    The Java side sends 'ip' as a nested object:
    {"adresse": "1.2.3.4", "isV6": false} (Gson serializes the IPAdress object
    directly). ChromaDB only accepts scalar metadata
    (str/int/float/bool), so it must ALWAYS be reduced to a string
    before being used as metadata.
    """
    if isinstance(raw_ip, dict):
        return raw_ip.get("adresse", "unknown")
    return raw_ip if raw_ip else "unknown"

# ==========================================
# BUSINESS FUNCTIONS
# ==========================================

def store_alert(alert_dict: Dict[str, Any]) -> str:
    """
    Store a security alert in the ChromaDB vector store.

    Args:
        alert_dict: A dictionary with keys: 'date', 'server', 'service', 'user', 'ip'
                    ('ip' can be a string or the nested object
                    {'adresse','isV6'} produced by Gson).

    Returns:
        A SHA-256 hex digest string that uniquely identifies the alert event.
    """
    ip_str = _flatten_ip(alert_dict.get("ip"))

    human_phrase = (
        f"On {alert_dict.get('date')}, an alert was detected on "
        f"server '{alert_dict.get('server')}' via {alert_dict.get('service')}. "
        f"Targeted user: '{alert_dict.get('user')}', source IP: {ip_str}."
    )

    identity = f"{alert_dict.get('date')}_{ip_str}"
    unique_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()

    # Strictly flat metadata (Chroma rejects nested dicts)
    metadata = {
        "date": alert_dict.get("date", ""),
        "server": alert_dict.get("server", ""),
        "service": alert_dict.get("service", ""),
        "user": alert_dict.get("user", "unknown"),
        "ip": ip_str,
    }

    document = Document(page_content=human_phrase, metadata=metadata)
    vector_store.add_documents(documents=[document], ids=[unique_id])

    return unique_id


def query_alerts(question: str, n_results: int = 5) -> List[Dict[str, Any]]:
    """Search the vector store for alerts semantically similar to the question."""
    results = vector_store.similarity_search(question, k=n_results)
    return [{"text": res.page_content, "details": res.metadata} for res in results]


def get_stats() -> Dict[str, List[Dict[str, Any]]]:
    """Retrieve statistics on top IPs and targeted users."""
    result = vector_store.get(include=["metadatas"])
    metas = result["metadatas"]

    ip_count: Dict[str, int] = {}
    user_count: Dict[str, int] = {}
    
    for m in metas:
        # Keys are 'ip' and 'user' (those written by store_alert)
        ip = m.get("ip", "unknown")
        user = m.get("user", "unknown")
        ip_count[ip] = ip_count.get(ip, 0) + 1
        user_count[user] = user_count.get(user, 0) + 1

    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_users = sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "top_ips": [{"ip": k, "count": v} for k, v in top_ips],
        "top_users": [{"user": k, "count": v} for k, v in top_users]
    }


def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve the most recent alerts."""
    result = vector_store.get(include=["documents", "metadatas"])
    alerts = []
    for doc, meta in zip(result["documents"], result["metadatas"]):
        alerts.append({"document": doc, **meta})
    return sorted(alerts, key=lambda x: _parse_syslog_date(x.get("date", "")), reverse=True)[:limit]
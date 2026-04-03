import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from entity_extractor import EntityExtractor
from groq_client import GroqClient
from models import AnalysisResponse, EntitiesModel, ThreatScoreModel
from prompts import ENTITY_EXTRACTION_PROMPT
from threat_scorer import KEYWORDS, calculate_base_score


MODEL_NAME = "llama-3.3-70b-versatile"

OUTPUT_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "precomputed_entities.json")
)

OUTPUT_RAW_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic_threats.json")
)


def _model_to_dict(model: Any) -> Dict[str, Any]:
    # Pydantic v1/v2 compatibility.
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _random_past_timestamp_iso() -> str:
    now = datetime.now(timezone.utc)
    days_ago = random.randint(1, 365)
    hours_ago = random.randint(0, 23)
    minutes_ago = random.randint(0, 59)
    dt = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
    return dt.isoformat()


def _clean_text_for_prompt(text: str) -> str:
    # Keep prompts stable and avoid accidental None inputs.
    return (text or "").strip()


def _build_messages() -> List[str]:
    # 0x wallets must be 40 hex chars after 0x.
    wallets = [
        "0x4a3b9c2d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7081",
        "0xbc9a8d7f6e5d4c3b2a1908f7e6d5c4b3a2f1e0d9",
        "0xa1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        "0xf0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d",
        "0x9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a39281716",
        "0x1111222233334444555566667777888899990000",
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "0x0123456789abcdef0123456789abcdef01234567",
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "0x0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6",
    ]

    companies = [
        "Acme Corp",
        "FinServe",
        "PaymentsCo",
        "Initech",
        "Umbrella Corp",
        "Wayne Enterprises",
        "Stark Industries",
        "Globex",
        "Soylent Corp",
        "AuthGate",
        "Atlas Systems",
        "ShadowOps",
        "CyberDyne",
        "Northwind Traders",
        "Megacorp",
        "VentureForge",
        "RavenWorks",
        "SableTech",
        "Orion Systems",
        "Redwood Labs",
    ]

    email_pool = [
        "admin@acme-support.com",
        "devops@acme.io",
        "support@acme-support.com",
        "ceo@acme.io",
        "analyst@finserve.co",
        "ops@wayne-enterprises.com",
        "ir@wayne-enterprises.com",
        "ciso@globex.example",
        "root@globex.example",
        "jane@globex.example",
        "security@initech.com",
        "breach@initech.com",
        "admin@initech.com",
        "contractors@initech.com",
        "finance@initech.com",
        "hr@initech.com",
        "help@umbrella-corp.com",
        "it@umbrella-corp.com",
        "creds@umbrella-corp.com",
        "ops@umbrella-corp.com",
        "sec@starkindustries.com",
        "partner@starkindustries.com",
        "leak@starkindustries.com",
        "payment@paymentsco.com",
        "leak@paymentsco.com",
        "db-admin@acme.io",
        "support@acme-support.com",
        "threat@finsrv.example",
        "attacker@soylentcorp.org",
        "partner@finsrv.example",
        "security@company.net",
        "ciso@company.net",
        "breach@company.net",
        "stolen@company.net",
        "payment@paymentsco.com",
        "ops@atlas-systems.com",
        "contact@cyberdyne.org",
        "chief@northwindtraders.co",
        "security@megasystems.dev",
        "ops@ventureforge.io",
        "red-team@ravenworks.net",
        "soc@sabletech.ai",
        "admin@orionsystems.com",
        "security@redwoodlabs.org",
        "security@authgate.example",
        "threat@shadowops.tld",
        "ir@atlas-systems.com",
        "ciso@globex.example",
        "leak@paymentsco.com",
        "exfil@initech.com",
    ]

    ip_pool = [
        "203.0.113.10",
        "203.0.113.77",
        "203.0.113.200",
        "203.0.113.8",
        "203.0.113.33",
        "203.0.113.144",
        "203.0.113.12",
        "203.0.113.13",
        "203.0.113.5",
        "203.0.113.6",
        "203.0.113.90",
        "203.0.113.91",
        "198.51.100.25",
        "198.51.100.26",
        "198.51.100.41",
        "198.51.100.42",
        "198.51.100.101",
        "198.51.100.102",
        "198.51.100.7",
        "198.51.100.5",
        "198.51.100.6",
        "198.51.100.250",
        "192.0.2.44",
        "192.0.2.99",
        "192.0.2.17",
        "192.0.2.18",
        "192.0.2.19",
        "192.0.2.55",
        "192.0.2.77",
        "192.0.2.88",
        "192.0.2.200",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.5",
    ]

    def pick(pool: List[str], i: int, step: int) -> str:
        return pool[(i * step) % len(pool)]

    templates = {
        "high_credentials": (
            "Selling leaked credentials from {company}. Emails: {email1}, {email2}, {email3}. "
            "IPs {ip1} and {ip2}. Payment to {wallet}. Records show a breach and stolen tokens."
        ),
        "high_zero_day": (
            "Zero-day exploit for {company}. Vulnerability details: connect to {ip1} and {ip2}. "
            "Targeted organizations include {company}. Wallet {wallet}; contact {email1} for the PoC."
        ),
        "high_ransomware": (
            "Ransomware bundle with C2 endpoints at {ip1} and {ip2}. Leaked credentials found across {company}. "
            "Emails: {email1}, {email2}, {email3}, {email4}. Transfer to {wallet} after hack."
        ),
        "high_database_dump": (
            "Database dump offered for {company}. Contains passwords for {email1}. IP {ip1} indicates prior exploit attempts. "
            "Stolen records available. Send to wallet {wallet}."
        ),
        "high_phishing_hack": (
            "Offering hacked access plus leaked credentials for {company}. Emails: {email1}, {email2}, {email3}. "
            "Seen from {ip1}. Payment wallet {wallet}. Hack confirmed."
        ),
        "medium_no_keywords": (
            "Listing compromised access for {company}. Emails: {email1}, {email2}, {email3}. Observed from {ip1}. "
            "Payment address {wallet}. No technical details shared."
        ),
        "low_no_wallet": (
            "Trade of access archives for {company}. Emails: {email1}, {email2}, {email3}. Observed from {ip1}. "
            "Buyer gets session history. Contact {email1}."
        ),
        "low_no_wallet_no_ip": (
            "Sharing a small batch of account dumps for {company}. Emails: {email1}, {email2}. "
            "Stored offline; no recent IP sightings. Payment accepted via {wallet}."
        ),
        "low_keywords_no_wallet": (
            "Selling leaked credentials tied to {company}. Emails: {email1}, {email2}, {email3}. "
            "IPs {ip1}. No wallet listed; buyer negotiates out-of-band. Breach chatter and stolen references."
        ),
        "medium_keywords_few_emails": (
            "Zero-day discussion about {company}. Exploit rumors circulate. Emails: {email1}, {email2}. "
            "Seen from {ip1}. Wallet withheld until confirmation."
        ),
    }

    scenarios = [
        "high_credentials",
        "high_zero_day",
        "high_ransomware",
        "high_database_dump",
        "high_phishing_hack",
        "medium_no_keywords",
        "low_no_wallet",
        "low_keywords_no_wallet",
        "medium_keywords_few_emails",
        "low_no_wallet_no_ip",
    ]

    products = ["payment gateway", "auth middleware", "CRM", "internal panel", "SSH service", "partner API", "admin console"]

    messages: List[str] = []
    for i in range(50):
        company = companies[i % len(companies)]
        wallet = wallets[i % len(wallets)]
        ip1 = pick(ip_pool, i, 2)
        ip2 = pick(ip_pool, i, 3)
        email1 = pick(email_pool, i, 5)
        email2 = pick(email_pool, i, 7)
        email3 = pick(email_pool, i, 11)
        email4 = pick(email_pool, i, 13)
        product = products[i % len(products)]

        scenario = scenarios[i % len(scenarios)]

        text = templates[scenario].format(
            company=company,
            wallet=wallet,
            ip1=ip1,
            ip2=ip2,
            email1=email1,
            email2=email2,
            email3=email3,
            email4=email4,
            product=product,
        )

        # Ensure low-variance: sometimes we remove wallets/IPs to vary regex entity counts.
        if scenario in {"low_no_wallet", "low_keywords_no_wallet", "medium_keywords_few_emails"}:
            # These templates are intentionally without a wallet. Keep them consistent.
            pass
        elif scenario == "low_no_wallet_no_ip":
            # This template includes a wallet but no IPs by design; it's used to vary wallets/emails without ips.
            # Replace any accidental IP-like tokens (none should exist, but keep safe).
            text = text.replace(ip1, "")

        messages.append(text)

    return messages


def _analyze_one(text: str, entity_extractor: EntityExtractor) -> AnalysisResponse:
    regex_entities = entity_extractor.extract_regex_entities(text)

    llm_data: Dict[str, Any] = {}
    llm_error: Dict[str, Any] | None = None
    try:
        groq_client = GroqClient(model=MODEL_NAME)
        prompt = ENTITY_EXTRACTION_PROMPT.format(text=text)
        llm_data = groq_client.analyze_text(prompt)
        if isinstance(llm_data, dict) and llm_data.get("error"):
            llm_error = llm_data
    except Exception as e:
        llm_error = {"error": "Groq init/request failed", "detail": str(e)}

    organizations: List[str] = []
    summary = ""
    if isinstance(llm_data, dict) and not llm_error:
        organizations_value = llm_data.get("organizations") or []
        if isinstance(organizations_value, list):
            organizations = [str(x) for x in organizations_value]
        elif organizations_value:
            organizations = [str(organizations_value)]
        summary = str(llm_data.get("summary") or "")

    if llm_error is not None:
        organizations = []
        summary = str((llm_data or {}).get("summary") or "")

    wallets = regex_entities.get("wallets") or []
    emails = regex_entities.get("emails") or []
    ips = regex_entities.get("ips") or []

    score, level = calculate_base_score(text, regex_entities)

    factors: List[str] = []
    text_lower = (text or "").lower()
    if any(keyword in text_lower for keyword in KEYWORDS):
        factors.append("keyword_match")
    if len(wallets) > 0:
        factors.append("wallets_present")
    if len(emails) > 2:
        factors.append("multiple_emails")
    if len(ips) > 0:
        factors.append("ips_present")

    return AnalysisResponse(
        entities=EntitiesModel(
            wallets=[str(x) for x in wallets],
            emails=[str(x) for x in emails],
            ips=[str(x) for x in ips],
            organizations=organizations,
        ),
        threat_score=ThreatScoreModel(score=score, level=level, factors=factors),
        summary=summary,
    )


def main() -> None:
    random.seed(42)

    entity_extractor = EntityExtractor()
    messages = _build_messages()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    with open(OUTPUT_RAW_PATH, "w", encoding="utf-8") as f:
        json.dump(messages, f, ensure_ascii=False)
    print(f"Wrote {len(messages)} raw messages to {OUTPUT_RAW_PATH}")

    results: List[Dict[str, Any]] = []
    total = len(messages)
    for i, message in enumerate(messages, start=1):
        print(f"Processing {i}/{total}...")
        cleaned = _clean_text_for_prompt(message)
        analysis = _analyze_one(cleaned, entity_extractor)

        results.append(
            {
                "id": str(uuid.uuid4()),
                "created_at": _random_past_timestamp_iso(),
                "input_text": cleaned,
                "analysis": _model_to_dict(analysis),
            }
        )

        time.sleep(1)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)

    print(f"Wrote {len(results)} records to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()


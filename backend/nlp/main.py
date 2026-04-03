from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from entity_extractor import EntityExtractor
from groq_client import GroqClient
from models import AnalysisResponse, EntitiesModel, ThreatScoreModel
from prompts import ENTITY_EXTRACTION_PROMPT
from threat_scorer import KEYWORDS, calculate_base_score


MODEL_NAME = "llama-3.3-70b-versatile"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/nlp/health")
def health():
    return {"status": "ok", "model": MODEL_NAME}


class ExtractEntitiesRequest(BaseModel):
    text: str


entity_extractor = EntityExtractor()


class AnalyzeTextRequest(BaseModel):
    text: str


@app.post("/api/nlp/extract/entities")
def extract_entities(payload: ExtractEntitiesRequest):
    return entity_extractor.extract_regex_entities(payload.text)


@app.post("/api/nlp/analyze/text", response_model=AnalysisResponse)
def analyze_text(payload: AnalyzeTextRequest):
    regex_entities = entity_extractor.extract_regex_entities(payload.text)

    llm_data = {}
    llm_error = None
    try:
        groq_client = GroqClient(model=MODEL_NAME)
        prompt = ENTITY_EXTRACTION_PROMPT.format(text=payload.text)
        llm_data = groq_client.analyze_text(prompt)
        if isinstance(llm_data, dict) and llm_data.get("error"):
            llm_error = llm_data
            print(f"LLM PIPELINE ERROR: {str(llm_error)}")
    except Exception as e:
        print(f"LLM PIPELINE ERROR: {str(e)}")
        llm_error = {"error": "Groq init/request failed", "detail": str(e)}

    organizations = []
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

    score, level = calculate_base_score(payload.text, regex_entities)

    factors = []
    text_lower = (payload.text or "").lower()
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


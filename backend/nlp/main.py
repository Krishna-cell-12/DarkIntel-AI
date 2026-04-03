from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from entity_extractor import EntityExtractor


MODEL_NAME = "mixtral-8x7b-32768"

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


@app.post("/api/nlp/extract/entities")
def extract_entities(payload: ExtractEntitiesRequest):
    return entity_extractor.extract_regex_entities(payload.text)


import json
import os
from typing import Any, Dict

from dotenv import load_dotenv
from groq import Groq


class GroqClient:
    def __init__(self, model: str = "mixtral-8x7b-32768") -> None:
        dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
        load_dotenv(dotenv_path=dotenv_path)
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("Missing GROQ_API_KEY in .env")

        self.model = model
        self.client = Groq(api_key=api_key)

    def analyze_text(self, prompt: str) -> Dict[str, Any]:
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                # Best-effort: asks the model to return a JSON object when supported.
                response_format={"type": "json_object"},
            )

            content = (
                completion.choices[0].message.content
                if completion and getattr(completion, "choices", None)
                else None
            )
            if content is None:
                return {"error": "Empty response from Groq"}

            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"error": "Model did not return valid JSON", "raw": content}

        except Exception as e:
            return {"error": "Groq request failed", "detail": str(e)}

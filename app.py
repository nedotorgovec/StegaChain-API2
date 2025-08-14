from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Literal

from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl import exceptions as nacl_exceptions
from nacl.encoding import Base64Encoder
import base64
import binascii

app = FastAPI(title="StegaChain API", version="0.1.0")

# --- CORS (разрешаем обращаться с любого фронтенда на этапе прототипа) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Модели ---
class EncryptRequest(BaseModel):
    message: str
    key: str  # base64/hex/32-byte ascii

class EncryptResponse(BaseModel):
    ciphertext_b64: str

class DecryptRequest(BaseModel):
    ciphertext_b64: str
    key: str  # base64/hex/32-byte ascii

class DecryptResponse(BaseModel):
    message: str

class KeyResponse(BaseModel):
    key: str
    fmt: Literal["base64"] = "base64"

# --- Утилиты ---

def parse_key(key_str: str) -> bytes:
    """Принимаем ключ в base64, hex или обычной ASCII-строке длиной 32 символа."""
    # 1) base64
    try:
        k = base64.b64decode(key_str, validate=True)
        if len(k) == 32:
            return k
    except (binascii.Error, ValueError):
        pass

    # 2) hex
    try:
        k = bytes.fromhex(key_str)
        if len(k) == 32:
            return k
    except ValueError:
        pass

    # 3) ascii (ровно 32 символа)
    if len(key_str) == 32:
        return key_str.encode("utf-8")

    raise HTTPException(status_code=400, detail="Key must be 32 bytes (accepts base64, hex, or 32-char ascii)")

# --- Эндпоинты ---

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/generate-key", response_model=KeyResponse)
async def generate_key():
    key_bytes = nacl_random(32)
    key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    return KeyResponse(key=key_b64)

@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt(req: EncryptRequest):
    key = parse_key(req.key)
    box = SecretBox(key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    try:
        encrypted = box.encrypt(req.message.encode("utf-8"), nonce)
        ct_b64 = Base64Encoder.encode(encrypted).decode("utf-8")
        return EncryptResponse(ciphertext_b64=ct_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encryption failed: {e}")

@app.post("/decrypt", response_model=DecryptResponse)
async def decrypt(req: DecryptRequest):
    key = parse_key(req.key)
    box = SecretBox(key)
    try:
        encrypted = Base64Encoder.decode(req.ciphertext_b64.encode("utf-8"))
        msg = box.decrypt(encrypted)
        return DecryptResponse(message=msg.decode("utf-8"))
    except (nacl_exceptions.CryptoError, ValueError, binascii.Error):
        raise HTTPException(status_code=400, detail="Decryption failed: wrong key or malformed ciphertext")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")

# Локальный запуск: uvicorn app:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

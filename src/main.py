from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import SDO, SRO, SCO
import utils

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "ThreatHawk Encoding is Running!"}


@app.post("/generate_sdo")
async def convert(sdo: SDO):
    return utils.generate_sdo(sdo)

@app.post("/generate_sro")
async def generate_sro(sro: SRO):
    return utils.generate_sro(sro)

@app.post("/generate_sco")
async def generate_sco(sco: SCO):
    return utils.generate_sco(sco)


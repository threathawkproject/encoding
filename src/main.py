from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import SDO
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


@app.post("/generate_sdo")
async def convert(sdo: SDO):
    print(f"sdo: {sdo}")
    return utils.convert(sdo)
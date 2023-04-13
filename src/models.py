from pydantic import BaseModel

from enum import Enum

class IndicatorType(Enum):
    IP = 'ip'
    Email = 'email'
    URL = 'url'
    MD5 = 'md5'
    SHA1 = 'sha1'
    SHA256 = 'sha256'

    def __str__(self):
        return self.value


class IndicatorDTO(BaseModel):
    value: str
    type: IndicatorType

class MalwareDTO(BaseModel):
    value: str
    is_family: bool


class AttackPatternDTO(BaseModel):
    name: str
    description: str
    external_references: list

class LocationDTO(BaseModel):
    name: str
    country: str
    latitude: float
    longitude: float


class DomainNameDTO(BaseModel):
    name: str


class SCO(BaseModel):
    type: str
    data: DomainNameDTO | None

class SRO(BaseModel):
    source: str
    target: str
    rel_type: str


class SDOType(BaseModel):
    INDICATOR = "indicator",
    MALWARE = "malware",
    ATTACK_PATTERN = "attack-pattern",
    LOCATION = "location",

class SDO(BaseModel):
    type: str
    data: IndicatorDTO | MalwareDTO | AttackPatternDTO | LocationDTO | None
    
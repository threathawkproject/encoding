from pydantic import BaseModel

from enum import Enum

class IndicatorType(Enum):
    IPv4 = 'ipv4'
    IPv6 = 'ipv6'
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

class Malware(BaseModel):
    pass


class SDO(BaseModel):
    type: str
    data: IndicatorDTO | None
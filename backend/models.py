from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class AttackRecord(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    src_ip: str = Field(..., description="Source IP address of the attack")
    dst_service: str = Field(..., description="Destination service (ssh, http, rdp, smb)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Attack timestamp")
    attack_type: Optional[str] = Field(None, description="Type of attack detected")
    payload: Optional[str] = Field(None, description="Attack payload or command")
    user_agent: Optional[str] = Field(None, description="User agent string")
    port: Optional[int] = Field(None, description="Target port")
    country: Optional[str] = Field(None, description="Source country (if geolocation available)")
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "src_ip": "192.168.1.100",
                "dst_service": "ssh",
                "attack_type": "brute_force",
                "payload": "admin:password",
                "user_agent": "SSH-2.0-OpenSSH_8.2p1",
                "port": 2222,
                "country": "US"
            }
        }


class AttackSummary(BaseModel):
    total_attacks: int
    unique_ips: int
    service_breakdown: Dict[str, int]
    recent_attacks: list[AttackRecord]
    top_attackers: list[Dict[str, Any]]


class DatabaseConfig(BaseModel):
    mongodb_uri: str = "mongodb://localhost:27017"
    database_name: str = "honeynet"
    collection_name: str = "attacks"

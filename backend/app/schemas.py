import ipaddress
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Status(str, Enum):
    new = "new"
    investigating = "investigating"
    closed = "closed"
    false_positive = "false_positive"


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=200)


class AlertIn(BaseModel):
    timestamp: str = Field(min_length=10, max_length=40, description="ISO-8601")
    source_ip: str
    dest_ip: Optional[str] = None
    signature: str = Field(min_length=3, max_length=300)
    severity: Severity = Severity.medium
    raw: Optional[str] = Field(default=None, max_length=10_000)

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def valid_ip(cls, v):
        if v is None:
            return v
        ipaddress.ip_address(v)  # ValueError -> HTTP 422
        return v


class StatusUpdate(BaseModel):
    status: Status


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)

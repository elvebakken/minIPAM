from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Dict, Any
from datetime import datetime

Role = Literal["admin", "readwrite", "readonly"]

class Icon(BaseModel):
    mime_type: str
    data_base64: str

class ReservedIP(BaseModel):
    ip: str
    reason: str = Field(default="", max_length=200)  # Max length enforced by validation

class Assignment(BaseModel):
    id: str
    ip: str
    hostname: str = Field(default="", max_length=255)  # RFC 1123 hostname max length
    type: str = Field(default="server", max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=20)  # Max 20 tags
    notes: str = Field(default="", max_length=5000)
    icon: Optional[Icon] = None
    archived: bool = False
    created_at: str
    updated_at: str

class Vlan(BaseModel):
    id: str
    name: str = Field(max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: str
    gateway_ip: Optional[str] = None
    reserved_ips: List[ReservedIP] = Field(default_factory=list)
    assignments: List[Assignment] = Field(default_factory=list)
    created_at: str
    updated_at: str

class Settings(BaseModel):
    type_options: List[str] = Field(default_factory=lambda: ["server", "docker", "network", "vm", "printer"])
    gateway_default: Literal["first_usable", "none"] = "first_usable"
    reserved_defaults: Dict[str, bool] = Field(default_factory=lambda: {
        "reserve_network": True,
        "reserve_broadcast": True,
        "reserve_gateway": True,
    })

class DataFile(BaseModel):
    schema_version: int = 1
    updated_at: str
    settings: Settings = Field(default_factory=Settings)
    vlans: List[Vlan] = Field(default_factory=list)

class User(BaseModel):
    id: str
    username: str
    password_bcrypt: str
    role: Role = "admin"
    created_at: str
    disabled: bool = False
    password_change_required: bool = False
    password_history: List[str] = Field(default_factory=list)  # Last 5 password hashes
    password_changed_at: Optional[str] = None  # ISO timestamp of last password change

class UsersFile(BaseModel):
    schema_version: int = 1
    updated_at: str
    users: List[User] = Field(default_factory=list)

class LoginRequest(BaseModel):
    username: str
    password: str

class MeResponse(BaseModel):
    username: str
    role: Role
    password_change_required: bool = False
    password_expires_at: Optional[str] = None  # ISO timestamp when password expires

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(max_length=50)  # Max length enforced by validation

class CreateVlanRequest(BaseModel):
    name: str = Field(max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: str

class PatchVlanRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: Optional[str] = None
    gateway_ip: Optional[str] = None

class CreateAssignmentRequest(BaseModel):
    ip: str
    hostname: str = Field(default="", max_length=255)  # RFC 1123 hostname max length
    type: str = Field(default="server", max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=20)  # Max 20 tags
    notes: str = Field(default="", max_length=5000)
    icon: Optional[Icon] = None

class PatchAssignmentRequest(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = Field(None, max_length=255)  # RFC 1123 hostname max length
    type: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = Field(None, max_length=20)  # Max 20 tags
    notes: Optional[str] = Field(None, max_length=5000)
    icon: Optional[Icon] = None
    archived: Optional[bool] = None

class PatchSettingsRequest(BaseModel):
    type_options: Optional[List[str]] = None
    gateway_default: Optional[str] = None
    reserved_defaults: Optional[Dict[str, bool]] = None

class CreateUserRequest(BaseModel):
    username: str = Field(max_length=50)  # Max length enforced by validation
    password: str
    role: Role = "readonly"

class PasswordStrengthRequest(BaseModel):
    password: str
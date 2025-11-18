"""
Database Schemas for Personal Finance App

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import date


class AuthUser(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: Optional[str] = None


class User(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    password_hash: str
    is_active: bool = True


class Category(BaseModel):
    name: str
    icon: Optional[str] = None
    type: Literal["income", "expense"] = "expense"
    color: Optional[str] = None


class Transaction(BaseModel):
    amount: float
    type: Literal["income", "expense"]
    category_id: Optional[str] = None
    category_name: Optional[str] = None
    note: Optional[str] = None
    date: date


class Budget(BaseModel):
    name: str
    month: str = Field(..., description="YYYY-MM")
    limit: float
    category_id: Optional[str] = None


class Goal(BaseModel):
    name: str
    target_amount: float
    current_amount: float = 0
    due_date: Optional[date] = None


class JWTToken(BaseModel):
    access_token: str
    token_type: str = "bearer"

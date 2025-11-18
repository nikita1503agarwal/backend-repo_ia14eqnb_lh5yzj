import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import AuthUser, User, Category, Transaction, Budget, Goal, JWTToken

# Environment
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Auth setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# FastAPI app
app = FastAPI(title="Personal Finance API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Helpers
class TokenData(BaseModel):
    email: Optional[str] = None

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str) -> Optional[dict]:
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db["user"].find_one({"email": email})


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user


# Public endpoints
@app.get("/")
def root():
    return {"message": "Personal Finance API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        from database import db as _db
        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = _db.name
            response["connection_status"] = "Connected"
            response["collections"] = _db.list_collection_names()[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/register", response_model=JWTToken)
def register(user: AuthUser):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    existing = get_user_by_email(user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = User(email=user.email, name=user.name, password_hash=get_password_hash(user.password), is_active=True)
    user_id = create_document("user", user_doc)
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/login", response_model=JWTToken)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}


# Category endpoints
@app.get("/categories")
def list_categories(current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return list(db["category"].find({"user_id": current_user.get("_id")}))

@app.post("/categories")
def create_category(category: Category, current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    data = category.model_dump()
    data["user_id"] = current_user.get("_id")
    cid = db["category"].insert_one(data).inserted_id
    return {"_id": str(cid), **data}


# Transaction endpoints
@app.get("/transactions")
def list_transactions(
    type: Optional[str] = None,
    category_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    query: dict = {"user_id": current_user.get("_id")}
    if type:
        query["type"] = type
    if category_id:
        try:
            query["category_id"] = ObjectId(category_id)
        except Exception:
            query["category_id"] = category_id
    if start_date or end_date:
        date_query = {}
        if start_date:
            date_query["$gte"] = datetime.fromisoformat(start_date)
        if end_date:
            date_query["$lte"] = datetime.fromisoformat(end_date)
        query["date"] = date_query
    txs = list(db["transaction"].find(query).sort("date", -1))
    return txs


@app.post("/transactions")
def create_transaction(tx: Transaction, current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    data = tx.model_dump()
    data["user_id"] = current_user.get("_id")
    # Convert date to datetime for storage consistency
    if isinstance(data.get("date"), str):
        data["date"] = datetime.fromisoformat(data["date"])  # type: ignore
    inserted_id = db["transaction"].insert_one(data).inserted_id
    return {"_id": str(inserted_id), **data}


@app.delete("/transactions/{tx_id}")
def delete_transaction(tx_id: str, current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    q = {"_id": ObjectId(tx_id), "user_id": current_user.get("_id")}
    result = db["transaction"].delete_one(q)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {"status": "deleted"}


# Budgets
@app.get("/budgets")
def list_budgets(current_user: dict = Depends(get_current_user)):
    return list(db["budget"].find({"user_id": current_user.get("_id")}))

@app.post("/budgets")
def create_budget(budget: Budget, current_user: dict = Depends(get_current_user)):
    data = budget.model_dump()
    data["user_id"] = current_user.get("_id")
    bid = db["budget"].insert_one(data).inserted_id
    return {"_id": str(bid), **data}


# Goals
@app.get("/goals")
def list_goals(current_user: dict = Depends(get_current_user)):
    return list(db["goal"].find({"user_id": current_user.get("_id")}))

@app.post("/goals")
def create_goal(goal: Goal, current_user: dict = Depends(get_current_user)):
    data = goal.model_dump()
    data["user_id"] = current_user.get("_id")
    gid = db["goal"].insert_one(data).inserted_id
    return {"_id": str(gid), **data}


# Dashboard summary
@app.get("/dashboard/summary")
def dashboard_summary(current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    pipeline = [
        {"$match": {"user_id": current_user.get("_id")}},
        {"$group": {
            "_id": "$type",
            "total": {"$sum": "$amount"}
        }}
    ]
    totals = {"income": 0.0, "expense": 0.0}
    for row in db["transaction"].aggregate(pipeline):
        totals[row["_id"]] = row["total"]
    balance = totals["income"] - totals["expense"]
    return {"total_income": totals["income"], "total_expenses": totals["expense"], "balance": balance}


# Demo data generator
@app.post("/demo")
def generate_demo(current_user: dict = Depends(get_current_user)):
    import random
    from datetime import timedelta

    categories = [
        {"name": "Salary", "type": "income"},
        {"name": "Food", "type": "expense"},
        {"name": "Transport", "type": "expense"},
        {"name": "Entertainment", "type": "expense"},
    ]
    inserted_cats = []
    for c in categories:
        c["user_id"] = current_user.get("_id")
        inserted_cats.append(db["category"].insert_one(c).inserted_id)

    for _ in range(20):
        is_income = random.random() < 0.3
        amount = round(random.uniform(10, 500), 2)
        cat_idx = 0 if is_income else random.randint(1, len(inserted_cats)-1)
        tx = {
            "amount": amount if is_income else -abs(amount),
            "type": "income" if is_income else "expense",
            "category_id": inserted_cats[cat_idx],
            "date": datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30)),
            "user_id": current_user.get("_id"),
            "note": "Demo"
        }
        db["transaction"].insert_one(tx)

    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

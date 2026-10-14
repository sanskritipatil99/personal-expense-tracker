from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import sqlite3
from pathlib import Path
from datetime import date
import os
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ 
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


DATABASE = str(Path(__file__).resolve().parent / "expenses.db")
print("DATABASE BEING USED: ", DATABASE)
# DATABASE ="expenses.db"

password_hash = PasswordHash.recommended()

SECRET_KEY = os.environ.get("EXPENSES_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "Set the EXPENSES_SECRET_KEY environment variable before starting the app."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

bearer_scheme = HTTPBearer()

def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

def initialize_database():
    with get_connection() as connection:
        # 1. Create the users table if it doesn't exist.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)

        # 2. Create the expenses table if it doesn't exist.
        connection.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount > 0),
            expense_date TEXT 
            )
        """)    
        # 3. Inspect the existing expenses table.
        columns = connection.execute(
            "PRAGMA table_info(expenses)"
        ).fetchall()

        column_names = [column["name"] for column in columns]
        # 4. Add user_id only if it is missing.
        if "user_id" not in column_names:
            connection.execute("""
                ALTER TABLE expenses
                ADD COLUMN user_id INTEGER REFERENCES users(id)
            """)
        # 5. Preserve compatibility with older databases.
        if "expense_date" not in column_names:
            connection.execute(
                "ALTER TABLE expenses ADD COLUMN expense_date TEXT"
            )

initialize_database()

def assign_existing_expenses(email: str):
    email = email.strip().lower()

    with get_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None:
            raise ValueError(
                "User not found. Register the account first."
            )

        connection.execute(
            """
            UPDATE expenses
            SET user_id = ?
            WHERE user_id IS NULL
            """,
            (user["id"],)
        )
def create_access_token(user_id: int):
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "exp": expires_at,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = int(payload["sub"])

    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, email FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return dict(user)

class ExpenseCreate(BaseModel):
    description:str = Field(min_length=1, max_length=100)
    category:str = Field(min_length=1, max_length=50)
    amount:float = Field(gt=0, le=1000000)
    expense_date: date

class UserCreate(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: str
    password: str

@app.post("/api/register", status_code=201)
def register_user(user: UserCreate):
    email = user.email.strip().lower()

    if not email or "@" not in email:
        raise HTTPException(
            status_code=422,
            detail="Enter a valid email address",
        )

    hashed_password = password_hash.hash(user.password)

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (email, password_hash)
                VALUES (?, ?)
                """,
                (email, hashed_password),
            )

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        )

    return {
        "message": "Account created successfully",
        "user_id": user_id,
        "email": email,
    }


@app.post("/api/login")
def login_user(user: UserLogin):
    email = user.email.strip().lower()

    with get_connection() as connection:
        account = connection.execute(
            """
            SELECT id, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    if account is None or not password_hash.verify(
        user.password,
        account["password_hash"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(account["id"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": account["id"],
        "email": account["email"],
    }    

@app.get("/")
def home():
    return {"message": "Welcome to Expense Tracker API!"}


@app.get("/api/expenses")
def get_expenses(current_user: dict = Depends(get_current_user)):
    print("Current user:", current_user)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, description, category, amount, expense_date
            FROM expenses 
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (current_user["id"],)
        ).fetchall()

    return [dict(row) for row in rows]   

@app.post("/api/expenses", status_code=201)
def create_expense(expense: ExpenseCreate, current_user: dict = Depends(get_current_user)):
    description = expense.description.strip()
    category = expense.category.strip()

    if not description or not category:
        raise HTTPException(
            status_code=422,
            detail="Description and category are blank"
        )

    with get_connection() as connection:
        cursor =  connection.execute(
            """
            INSERT INTO expenses (description, category, amount, expense_date, user_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (description,category,expense.amount, expense.expense_date.isoformat(), current_user["id"])
        )

        expense_id = cursor.lastrowid

        row = connection.execute(
            """
            SELECT id, description, category, amount, expense_date
            FROM expenses WHERE id = ? AND user_id = ?
            """,
            (expense_id, current_user["id"])
        ).fetchone()

    return dict(row)
@app.get("/debug/database")
def debug_database():
    with get_connection() as connection:
        database = connection.execute(
            "PRAGMA database_list"
        ).fetchone()

        columns = connection.execute(
            "PRAGMA table_info(expenses)"
        ).fetchall()

        table = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'expenses'
            """
        ).fetchone()

    return {
        "database_path": database["file"],
        "columns": [column["name"] for column in columns],
        "table_definition": table["sql"] if table else None
    }
@app.get("/debug/expense-ownership")
def debug_expense_ownership():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, description, user_id
            FROM expenses
            ORDER BY id
        """).fetchall()

    return [dict(row) for row in rows]
    
@app.delete("/api/expenses/{expense_id}")
def delete_expense(
    expense_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_connection() as connection:
        cursor = connection.execute(
            """
            DELETE FROM expenses
            WHERE id = ? AND user_id = ?
            """,
            (expense_id, current_user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Expense not found"
            )

    return {"message": "Expense deleted successfully"}

@app.put("/api/expenses/{expense_id}")  
def update_expense(
    expense_id: int,
    expense: ExpenseCreate,
    current_user: dict = Depends(get_current_user)
):
    description = expense.description.strip()
    category = expense.category.strip()

    if not description or not category:
        raise HTTPException(
            status_code=422,
            detail="Description and category are blank"
        )

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE expenses
            SET description = ?, category = ?, amount = ?, expense_date = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                description,
                category,
                expense.amount,
                expense.expense_date.isoformat(),
                expense_id,
                current_user["id"]
            )
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Expense not found"
            )

        row = connection.execute(
            """
            SELECT id, description, category, amount, expense_date
            FROM expenses
            WHERE id = ? AND user_id = ?
            """,
            (expense_id, current_user["id"])
        ).fetchone()

    return dict(row)   
# assign_existing_expenses("test@example.com") 

@app.get("/debug/users")
def debug_users():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, email FROM users"
        ).fetchall()

    return [dict(row) for row in rows]
# if __name__ == "__main__":
#     with get_connection() as connection:
#         print("Database file:", DATABASE)

#         columns = connection.execute(
#             "PRAGMA table_info(expenses)"
#         ).fetchall()

#         print("Table columns:", [column["name"] for column in columns]) 
# cd "$HOME\OneDrive\Desktop\Building Project"
# .\.venv313\Scripts\python.exe -m uvicorn main:app --reload
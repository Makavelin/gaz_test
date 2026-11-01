from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_jwt import JwtAccessBearer, JwtAuthorizationCredentials
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Users API with JWT")
templates = Jinja2Templates(directory="templates")

access_security = JwtAccessBearer(secret_key="very_secret_key", auto_error=True)


class User(BaseModel):
    id: Optional[int] = None
    name: str
    email: EmailStr


class UserInDB(User):
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str



users_db: List[UserInDB] = []
next_id = 1



def find_user_by_email(email: str) -> Optional[UserInDB]:
    for u in users_db:
        if u.email == email:
            return u
    return None


def login_user(payload: UserLogin) -> str:
    user_in_db = find_user_by_email(payload.email)
    if user_in_db is None or user_in_db.password != payload.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return access_security.create_access_token(subject=user_in_db.model_dump())



@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request})



@app.post("/auth")
def auth(payload: UserLogin):
    token = login_user(payload)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register", response_model=User, status_code=201)
def register(payload: RegisterRequest):
    global next_id
    if find_user_by_email(payload.email) is not None:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserInDB(
        id=next_id,
        name=payload.name,
        email=payload.email,
        password=payload.password,
    )
    users_db.append(user)
    next_id += 1
    return User(id=user.id, name=user.name, email=user.email)


@app.get("/me", response_model=User)
def me(credentials: JwtAuthorizationCredentials = Security(access_security)):
    sub = credentials.subject
    return User(id=sub.get("id"), name=sub.get("name"), email=sub.get("email"))



@app.post("/users", response_model=User, status_code=201)
def create_user(
    payload: User,
    credentials: JwtAuthorizationCredentials = Security(access_security),
):
    global next_id
    user = UserInDB(
        id=next_id,
        name=payload.name,
        email=payload.email,
        password="default",
    )
    users_db.append(user)
    next_id += 1
    return User(id=user.id, name=user.name, email=user.email)


@app.get("/users", response_model=List[User])
def list_users(credentials: JwtAuthorizationCredentials = Security(access_security)):
    return [User(id=u.id, name=u.name, email=u.email) for u in users_db]

@app.get("/users/{user_id}", response_model=User)
def get_user(
    user_id: int,
    credentials: JwtAuthorizationCredentials = Security(access_security),
):
    for u in users_db:
        if u.id == user_id:
            return User(id=u.id, name=u.name, email=u.email)
    raise HTTPException(status_code=404, detail="User not found")


@app.put("/users/{user_id}", response_model=User)
def update_user(
    user_id: int,
    payload: User,
    credentials: JwtAuthorizationCredentials = Security(access_security),
):
    for i in range(len(users_db)):
        if users_db[i].id == user_id:
            users_db[i].name = payload.name
            users_db[i].email = payload.email
            u = users_db[i]
            return User(id=u.id, name=u.name, email=u.email)
    raise HTTPException(status_code=404, detail="User not found")



@app.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    credentials: JwtAuthorizationCredentials = Security(access_security),
):
    for i in range(len(users_db)):
        if users_db[i].id == user_id:
            users_db.pop(i)
            return
    raise HTTPException(status_code=404, detail="User not found")
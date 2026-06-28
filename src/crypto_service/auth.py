import os
from datetime import datetime, timedelta, timezone

import jwt
from jwt import InvalidTokenError
from pydantic import BaseModel
from pwdlib import PasswordHash


from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

############################# JWT #############################

JWT_SECRET_KEY = os.getenv( 
    "JWT_SECRET_KEY",
    "change-this-demo-secret-in-production", # Secret key for signing JWT tokens (should be changed in production)
)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended() # Recommended password hashing algorithm (Argon2id) for secure password storage

oauth2_scheme = OAuth2PasswordBearer( # It indicates that FastAPI that the app will use OAuth2 with password and bearer token, obtained from the /auth/login endpoint, for authentication. 
    tokenUrl="/auth/login"
)


############################## USER AND TOKEN MODELS ##############################

class User(BaseModel):
    username: str
    hashed_password: str
    role: str


class TokenData(BaseModel):
    username: str
    role: str

############################## DEMO USERS #############################

def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)


def create_demo_user(
    username: str,
    plain_password: str,
    role: str,
) -> User:
    return User(
        username=username,
        hashed_password=hash_password(plain_password),
        role=role,
    )


DEMO_USERS = {
    "admin": create_demo_user(
        username="admin",

        plain_password="admin123",
        role="admin",
    ),
    "viewer": create_demo_user(
        username="viewer",
        plain_password="viewer123",
        role="viewer",
    ),
}


############################## AUTHENTICATION AND TOKEN FUNCTIONS #############################


def verify_password( # Verifies a plain password against a hashed password using the configured password hashing algorithm
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password,
    )


def get_user(username: str) -> User | None: # Retrieves a user from the hardcoded demo users based on the username
    return DEMO_USERS.get(username)


def authenticate_user( # Authenticates a user by verifying the username and password against the hardcoded demo users 
    username: str,
    password: str,
) -> User | None:
    user = get_user(username) # Verify if there is a user with the provided username in the hardcoded demo users

    if user is None:
        return None

    if not verify_password( # Verifies the provided password against the stored hashed password for the user
        plain_password=password,
        hashed_password=user.hashed_password,
    ):
        return None

    return user


def create_access_token( # Creates a JWT access token for a user with a specified expiration time
    username: str,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    if expires_delta is None:
        expires_delta = timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )

    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    ) 


def decode_access_token(token: str) -> TokenData:  # Decodes a JWT access token and returns the token data (username and role) if valid, otherwise raises a ValueError
    try:
        payload = jwt.decode( # Decodes the JWT token using the secret key and algorithm, and retrieves the payload (claims) from the token.
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
    except InvalidTokenError as exc:
        raise ValueError("Invalid access token.") from exc

    username = payload.get("sub")
    role = payload.get("role")

    if not isinstance(username, str):
        raise ValueError("Token does not contain a valid subject.")

    if not isinstance(role, str):
        raise ValueError("Token does not contain a valid role.")

    return TokenData(
        username=username,
        role=role,
    )

def get_current_user( # It analyzes the validity by decoding the JWT token and retrieving the user from the hardcoded demo users. 
    token: str = Depends(oauth2_scheme),
) -> User:
    try:
        token_data = decode_access_token(token) # Decodes the JWT token to retrieve the token data (username and role)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = get_user(token_data.username) #If the token is valid, retrieves the user from the hardcoded demo users based on the username in the token data.

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
import jwt

# Your token
token_str = ""

# Replace with your Django secret key
SECRET_KEY = "django-insecure-mt=7971#o+6h2k*uwmm44oi7)#d9k*#xd=i%=0%@kz4g^d^o0k"

try:
    payload = jwt.decode(token_str, SECRET_KEY, algorithms=["HS256"])
    print("Decoded Payload:", payload)
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError:
    print("Invalid Token.")

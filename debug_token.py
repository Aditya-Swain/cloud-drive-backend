import jwt

# Your token
token_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzM0NTAzNjU4LCJpYXQiOjE3MzQ0MTcyNTgsImp0aSI6ImE1NmJiYjc4NDExNzRkM2VhYjc5ODUzMmM1NTQzNjZiIiwidXNlcl9pZCI6MX0.9rZK3ZgHh5JWDHjJR7TtjOwif2oDgtVQbPqJXSKe7NQ"

# Replace with your Django secret key
SECRET_KEY = "django-insecure-mt=7971#o+6h2k*uwmm44oi7)#d9k*#xd=i%=0%@kz4g^d^o0k"

try:
    payload = jwt.decode(token_str, SECRET_KEY, algorithms=["HS256"])
    print("Decoded Payload:", payload)
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError:
    print("Invalid Token.")

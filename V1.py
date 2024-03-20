import jwt
from datetime import datetime, timedelta
import hashlib
import secrets


clave_secreta = secrets.token_hex(16)

base_de_datos_usuarios = {}


def autenticar_usuario(nombre_usuario, contrasena):
    if nombre_usuario in base_de_datos_usuarios:
        hashed_password, salt = base_de_datos_usuarios[nombre_usuario]
        hash_input = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), salt, 100000)
        if hashed_password == hash_input:
            return True
    return False


def registrar_usuario(nombre_usuario, contrasena):
    if nombre_usuario in base_de_datos_usuarios:
        return False  
    else:
        salt = secrets.token_bytes(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), salt, 100000)
        base_de_datos_usuarios[nombre_usuario] = (hashed_password, salt)
        return True


def generar_token(nombre_usuario, rol='usuario'):
    
    payload = {
        'nombre_usuario': nombre_usuario,
        'rol': rol,
        'exp': datetime.utcnow() + timedelta(minutes=30)  
    }

   
    token = jwt.encode(payload, clave_secreta, algorithm='HS256')

    return token

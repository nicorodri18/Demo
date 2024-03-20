import jwt
from datetime import datetime, timedelta
import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox


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
        'exp': datetime.utcnow() + timedelta(minutes=30)     }

    
    token = jwt.encode(payload, clave_secreta, algorithm='HS256')

    return token

def iniciar_sesion():
    nombre_usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    if autenticar_usuario(nombre_usuario, contrasena):
        messagebox.showinfo('Inicio de sesión exitoso', 'Autenticación exitosa')
    else:
        messagebox.showerror('Error de autenticación', 'Autenticación fallida. Credenciales inválidas.')


def registrar():
    nuevo_usuario = entry_usuario.get()
    nueva_contrasena = entry_contrasena.get()
    if registrar_usuario(nuevo_usuario, nueva_contrasena):
        messagebox.showinfo('Registro exitoso', f'Usuario {nuevo_usuario} registrado correctamente.')
    else:
        messagebox.showerror('Error de registro', f'Error: El usuario {nuevo_usuario} ya existe.')


ventana = tk.Tk()
ventana.title('Demo de autenticación y autorización')


tk.Label(ventana, text='Nombre de usuario:').pack()
entry_usuario = tk.Entry(ventana)
entry_usuario.pack()

tk.Label(ventana, text='Contraseña:').pack()
entry_contrasena = tk.Entry(ventana, show='*')
entry_contrasena.pack()


btn_iniciar_sesion = tk.Button(ventana, text='Iniciar Sesión', command=iniciar_sesion)
btn_iniciar_sesion.pack(pady=10)

btn_registrar = tk.Button(ventana, text='Registrarse', command=registrar)
btn_registrar.pack(pady=5)


ventana.mainloop()

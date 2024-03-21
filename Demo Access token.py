import jwt
from datetime import datetime, timedelta
import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox
import pyperclip

# Clave secreta para firmar y verificar los tokens JWT
clave_secreta = secrets.token_hex(16)
# Base de datos simulada de usuarios
base_de_datos_usuarios = {}

# Función para simular la autenticación del usuario
def autenticar_usuario(nombre_usuario, contrasena):
    if nombre_usuario in base_de_datos_usuarios:
        hashed_password, salt = base_de_datos_usuarios[nombre_usuario]
        hash_input = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), salt, 100000)
        if hashed_password == hash_input:
            return True
    return False

# Función para registrar un nuevo usuario
def registrar_usuario(nombre_usuario, contrasena):
    if nombre_usuario in base_de_datos_usuarios:
        return False  # El nombre de usuario ya existe
    else:
        salt = secrets.token_bytes(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), salt, 100000)
        base_de_datos_usuarios[nombre_usuario] = (hashed_password, salt)
        return True

# Función para generar un token de acceso JWT después de la autenticación exitosa
def generar_token(nombre_usuario, rol='usuario'):
    # Crear el payload para el token JWT
    payload = {
        'nombre_usuario': nombre_usuario,
        'rol': rol,
        'exp': datetime.utcnow() + timedelta(minutes=30)  # Token de acceso válido por 30 minutos
    }

    # Generar el token JWT
    token = jwt.encode(payload, clave_secreta, algorithm='HS256')

    return token

# Función para verificar el token de acceso
def verificar_token(token):
    try:
        payload = jwt.decode(token, clave_secreta, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'mensaje': 'Token de acceso expirado'}
    except jwt.InvalidTokenError:
        return {'mensaje': 'Token de acceso inválido'}

# Función para manejar el evento de inicio de sesión en la GUI
def iniciar_sesion():
    nombre_usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    if autenticar_usuario(nombre_usuario, contrasena):
        access_token = generar_token(nombre_usuario)
        messagebox.showinfo('Inicio de sesión exitoso', f'Se ha generado el token de acceso: {access_token}')
        ventana_verificacion(access_token)
    else:
        messagebox.showerror('Error de autenticación', 'Autenticación fallida. Credenciales inválidas.')
        ventana.destroy()

# Función para abrir la ventana de verificación de token en la GUI
def ventana_verificacion(token):
    ventana_verificacion = tk.Toplevel()
    ventana_verificacion.title('Verificar Token de Acceso')

    tk.Label(ventana_verificacion, text='Token de acceso:').pack()
    entry_token = tk.Entry(ventana_verificacion, width=50)
    entry_token.insert(0, token)
    entry_token.pack()

    btn_copiar = tk.Button(ventana_verificacion, text='Copiar Token', command=lambda: copiar_token(token))
    btn_copiar.pack(pady=5)

    btn_verificar = tk.Button(ventana_verificacion, text='Verificar Token', command=lambda: verificar_token_gui(entry_token.get()))
    btn_verificar.pack(pady=10)

def copiar_token(token):
    pyperclip.copy(token)
    messagebox.showinfo('Token copiado', 'El token de acceso ha sido copiado al portapapeles.')

def verificar_token_gui(token):
    resultado_verificacion = verificar_token(token)
    if 'mensaje' in resultado_verificacion:
        messagebox.showerror('Error de verificación', resultado_verificacion['mensaje'])
        ventana.destroy()
    else:
        messagebox.showinfo('Verificación exitosa', 'Token de acceso verificado correctamente.')

# Función para manejar el evento de registro en la GUI
def registrar():
    nuevo_usuario = entry_usuario.get()
    nueva_contrasena = entry_contrasena.get()
    if registrar_usuario(nuevo_usuario, nueva_contrasena):
        messagebox.showinfo('Registro exitoso', f'Usuario {nuevo_usuario} registrado correctamente.')
    else:
        messagebox.showerror('Error de registro', f'Error: El usuario {nuevo_usuario} ya existe.')

# Crear la ventana principal de la GUI
ventana = tk.Tk()
ventana.title('Demo de autenticación y autorización')

# Crear etiquetas y campos de entrada para usuario y contraseña
tk.Label(ventana, text='Nombre de usuario:').pack()
entry_usuario = tk.Entry(ventana)
entry_usuario.pack()

tk.Label(ventana, text='Contraseña:').pack()
entry_contrasena = tk.Entry(ventana, show='*')
entry_contrasena.pack()

# Botones para iniciar sesión y registrarse
btn_iniciar_sesion = tk.Button(ventana, text='Iniciar Sesión', command=iniciar_sesion)
btn_iniciar_sesion.pack(pady=10)

btn_registrar = tk.Button(ventana, text='Registrarse', command=registrar)
btn_registrar.pack(pady=5)

# Ejecutar la interfaz gráfica
ventana.mainloop()

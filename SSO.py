import jwt
from datetime import datetime, timedelta
import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox


clave_secreta = secrets.token_hex(16)


base_de_datos_usuarios = {
    'usuario1': {
        'contrasena': 'contrasena1',
        'roles': ['admin', 'usuario']
    }
}

def autenticar_usuario(nombre_usuario, contrasena):
    if nombre_usuario in base_de_datos_usuarios and base_de_datos_usuarios[nombre_usuario]['contrasena'] == contrasena:
        return True
    return False


def generar_token(nombre_usuario, rol='usuario'):
    payload = {
        'nombre_usuario': nombre_usuario,
        'rol': rol,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    token = jwt.encode(payload, clave_secreta, algorithm='HS256')
    return token


def verificar_token(token):
    try:
        payload = jwt.decode(token, clave_secreta, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'mensaje': 'Token de acceso expirado'}
    except jwt.InvalidTokenError:
        return {'mensaje': 'Token de acceso inválido'}


def iniciar_sesion():
    nombre_usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    if autenticar_usuario(nombre_usuario, contrasena):
        access_token = generar_token(nombre_usuario)
        messagebox.showinfo('Inicio de sesión exitoso', f'Se ha generado el token de acceso: {access_token}')
        verificar_aplicacion(access_token)
    else:
        messagebox.showerror('Error de autenticación', 'Autenticación fallida. Credenciales inválidas.')


def verificar_aplicacion(token):
    ventana_aplicacion = tk.Toplevel()
    ventana_aplicacion.title('Verificar Aplicación y Token de Acceso')

    tk.Label(ventana_aplicacion, text='Ingrese el nombre de la aplicación:').pack()
    entry_aplicacion = tk.Entry(ventana_aplicacion)
    entry_aplicacion.pack()

    btn_verificar = tk.Button(ventana_aplicacion, text='Verificar', command=lambda: verificar_token_aplicacion(entry_aplicacion.get(), token))
    btn_verificar.pack(pady=10)


def verificar_token_aplicacion(aplicacion, token):
    resultado_verificacion = verificar_token(token)
    if 'nombre_usuario' in resultado_verificacion and aplicacion in base_de_datos_usuarios[resultado_verificacion['nombre_usuario']]['roles']:
        messagebox.showinfo('Verificación exitosa', f'Token de acceso válido para la aplicación: {aplicacion}')
    else:
        messagebox.showerror('Error de verificación', f'Token de acceso inválido para la aplicación: {aplicacion}')


ventana = tk.Tk()
ventana.title('Demo de Single Sign-On (SSO)')


tk.Label(ventana, text='Nombre de usuario:').pack()
entry_usuario = tk.Entry(ventana)
entry_usuario.pack()

tk.Label(ventana, text='Contraseña:').pack()
entry_contrasena = tk.Entry(ventana, show='*')
entry_contrasena.pack()


btn_iniciar_sesion = tk.Button(ventana, text='Iniciar Sesión', command=iniciar_sesion)
btn_iniciar_sesion.pack(pady=10)


ventana.mainloop()

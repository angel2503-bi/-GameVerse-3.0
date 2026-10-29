import os
from datetime import datetime, timezone
from functools import wraps
import secrets
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, abort, jsonify, session, flash
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson import ObjectId
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or (secrets.token_hex(32) if not os.environ.get("RENDER") else "")
if not app.secret_key:
    raise RuntimeError("Configura SECRET_KEY en Render.")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")))
mongo_uri = os.environ.get('MONGO_URI')
if not mongo_uri:
    if os.environ.get('RENDER'):
        raise RuntimeError('Configura MONGO_URI en Render.')
    mongo_uri = 'mongodb://127.0.0.1:27017/'
cliente = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
juegos = cliente[os.environ.get('MONGO_DB_NAME', 'game_shop_nuevo')]['videojuegos']
usuarios = cliente[os.environ.get('MONGO_DB_NAME', 'game_shop_nuevo')]['usuarios']
pedidos = cliente[os.environ.get('MONGO_DB_NAME', 'game_shop_nuevo')]['pedidos']
CATEGORIAS = ['Acción','Aventura','Terror','Carreras','Deportes','Estrategia','RPG','Simulación','Multijugador','Otros']

CAMPOS_REQUISITOS = tuple(f'{nivel}_{campo}' for nivel in ('min', 'rec') for campo in ('so','procesador','ram','grafica','directx','almacenamiento','notas'))

def validar_imagen(url):
    if not url: return ''
    p = urlparse(url)
    if p.scheme not in ('https', 'http') or not p.netloc:
        abort(400, description='La imagen debe ser una URL http o https válida.')
    return url

def leer_datos(origen):
    nombre = str(origen.get('nombre','')).strip()
    categoria = str(origen.get('categoria','')).strip()
    descripcion = str(origen.get('descripcion','')).strip()
    desarrollador = str(origen.get('desarrollador','')).strip()
    imagen = str(origen.get('imagen','')).strip()
    banner = str(origen.get('banner','')).strip()
    requisitos = {campo: str(origen.get(campo, '')).strip() for campo in CAMPOS_REQUISITOS}
    if any(len(v) > 300 for v in requisitos.values()):
        abort(400, description='Cada requisito admite un máximo de 300 caracteres.')
    try:
        precio = float(origen.get('precio', 0))
        stock = int(origen.get('stock', 0))
    except (TypeError, ValueError):
        abort(400, description='Precio y stock deben ser números válidos.')
    if not nombre or not categoria:
        abort(400, description='Completa nombre y categoría.')
    if len(nombre)>100 or len(categoria)>40 or len(descripcion)>2000 or len(desarrollador)>100:
        abort(400, description='Uno de los campos supera el máximo permitido.')
    if precio<0 or stock<0 or precio>1000000 or stock>1000000:
        abort(400, description='Precio y stock deben ser valores válidos no negativos.')
    if len(imagen)>1000 or len(banner)>1000:
        abort(400, description='La URL de imagen es demasiado larga.')
    return dict(nombre=nombre,categoria=categoria,descripcion=descripcion,desarrollador=desarrollador,
                precio=precio,stock=stock,imagen=validar_imagen(imagen),banner=validar_imagen(banner), **requisitos)

def buscar_juego(id):
    if not ObjectId.is_valid(id): abort(404, description='ID inválido.')
    juego = juegos.find_one({'_id':ObjectId(id)})
    if not juego: abort(404, description='Videojuego no encontrado.')
    return juego

def serializar(j):
    return {'id':str(j['_id']),**{k:j.get(k, '' if k not in ('precio','stock') else 0) for k in
        ('nombre','categoria','descripcion','desarrollador','precio','stock','imagen','banner', *CAMPOS_REQUISITOS)}}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('usuario_id'):
            flash('Inicia sesión para finalizar tu compra.', 'info')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper
def es_administrador():
    """Solo la cuenta cuyo correo coincide con ADMIN_EMAIL puede administrar."""
    correo_admin = os.environ.get('ADMIN_EMAIL', '').strip().lower()
    usuario_id = session.get('usuario_id', '')
    if not correo_admin or not ObjectId.is_valid(usuario_id):
        return False
    usuario = usuarios.find_one({'_id': ObjectId(usuario_id)})
    return bool(usuario and usuario.get('correo', '').strip().lower() == correo_admin)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('usuario_id'):
            flash('Inicia sesión con tu cuenta de administrador.', 'info')
            return redirect(url_for('login'))
        if not es_administrador():
            abort(403, description='Acceso exclusivo del administrador.')
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def proteger_api_admin():
    # Consultas públicas; cualquier cambio de catálogo exige cuenta administradora.
    if request.path.startswith('/api/videojuegos') and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        if not es_administrador():
            return jsonify(error='Acceso exclusivo del administrador. Inicia sesión como administrador.'), 403


@app.context_processor
def datos_sesion():
    return {'usuario_actual': session.get('usuario_nombre'), 'carrito_cantidad': sum(session.get('carrito', {}).values()), 'es_admin': es_administrador()}

@app.before_request
def proteger_formularios():
    if request.method == 'POST' and not request.path.startswith('/api/'):
        token = session.get('csrf_token')
        if not token or not secrets.compare_digest(request.form.get('_csrf', ''), token):
            abort(400, description='Formulario caducado. Actualiza la página e inténtalo nuevamente.')

@app.context_processor
def csrf_template():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(24)
    return {'csrf_token': session['csrf_token']}

@app.route('/crear-cuenta', methods=['GET','POST'])
def crear_cuenta():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip().lower()
        clave = request.form.get('clave', '')
        if not (2 <= len(nombre) <= 80) or not (5 <= len(correo) <= 254) or '@' not in correo or not (8 <= len(clave) <= 128):
            flash('Revisa los datos. La contraseña debe tener al menos 8 caracteres.', 'error')
        elif correo == os.environ.get('ADMIN_EMAIL', '').strip().lower() and (not os.environ.get('ADMIN_SETUP_TOKEN') or not secrets.compare_digest(request.form.get('admin_setup_token', ''), os.environ['ADMIN_SETUP_TOKEN'])):
            flash('Para crear la cuenta administradora necesitas el código de configuración.', 'error')
        elif usuarios.find_one({'correo': correo}):
            flash('Ese correo ya está registrado.', 'error')
        else:
            usuarios.create_index('correo', unique=True)
            from pymongo.errors import DuplicateKeyError
            try:
                doc = usuarios.insert_one({'nombre':nombre,'correo':correo,'clave_hash':generate_password_hash(clave),'creado':datetime.now(timezone.utc)})
                session.clear()
                session['usuario_id'] = str(doc.inserted_id)
                session['usuario_nombre'] = nombre
                flash('¡Cuenta creada correctamente!', 'ok')
                return redirect(url_for('carrito'))
            except DuplicateKeyError:
                flash('Ese correo ya está registrado.', 'error')
    return render_template('crear_cuenta.html')

@app.route('/iniciar-sesion', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip().lower()
        usuario = usuarios.find_one({'correo':correo})
        if usuario and check_password_hash(usuario['clave_hash'], request.form.get('clave','')):
            carrito_guardado = session.get('carrito', {})
            session.clear()
            session['usuario_id'] = str(usuario['_id'])
            session['usuario_nombre'] = usuario['nombre']
            session['carrito'] = carrito_guardado
            flash('¡Bienvenido a Game Shop!', 'ok')
            return redirect(url_for('carrito'))
        flash('Correo o contraseña incorrectos.', 'error')
    return render_template('login.html')

@app.route('/cerrar-sesion', methods=['POST'])
def logout():
    session.clear()
    flash('Sesión cerrada.', 'ok')
    return redirect(url_for('inicio'))

@app.route('/carrito/agregar/<id>', methods=['POST'])
def carrito_agregar(id):
    juego = buscar_juego(id)
    carrito = dict(session.get('carrito', {}))
    if int(juego.get('stock',0)) <= int(carrito.get(id,0)):
        flash('No hay suficientes unidades disponibles.', 'error')
    else:
        carrito[id] = int(carrito.get(id,0)) + 1
        session['carrito'] = carrito
        flash('Videojuego agregado al carrito.', 'ok')
    return redirect(url_for('carrito'))

@app.route('/carrito')
def carrito():
    elementos = []
    total = 0
    for id, cantidad in session.get('carrito', {}).items():
        if not ObjectId.is_valid(id): continue
        juego = juegos.find_one({'_id':ObjectId(id)})
        if juego:
            subtotal = round(float(juego['precio']) * int(cantidad),2)
            total += subtotal
            elementos.append({'juego':juego,'cantidad':cantidad,'subtotal':subtotal})
    return render_template('carrito.html', elementos=elementos, total=round(total,2))

@app.route('/carrito/quitar/<id>', methods=['POST'])
def carrito_quitar(id):
    carrito = dict(session.get('carrito', {}))
    carrito.pop(id, None)
    session['carrito'] = carrito
    return redirect(url_for('carrito'))

@app.route('/comprar', methods=['POST'])
@login_required
def comprar():
    carrito = session.get('carrito', {})
    if not carrito:
        flash('Tu carrito está vacío.', 'error')
        return redirect(url_for('carrito'))
    items=[]
    for id, cantidad in carrito.items():
        if not ObjectId.is_valid(id) or not isinstance(cantidad,int) or cantidad < 1 or cantidad > 100:
            abort(400, description='Carrito inválido.')
        juego=juegos.find_one({'_id':ObjectId(id)})
        if not juego or int(juego.get('stock',0)) < cantidad:
            flash('Algún videojuego ya no tiene existencias suficientes.', 'error')
            return redirect(url_for('carrito'))
        items.append({'id':id,'nombre':juego['nombre'],'cantidad':cantidad,'precio':float(juego['precio'])})
    # Compra simulada: no descuenta stock para evitar reservas parciales sin transacciones.
    total=round(sum(i['precio']*i['cantidad'] for i in items),2)
    pedidos.insert_one({'usuario_id':ObjectId(session['usuario_id']),'items':items,'total':total,'fecha':datetime.now(timezone.utc),'estado':'Simulada'})
    session['carrito']={}
    flash('¡Compra simulada registrada correctamente! No se realizó ningún cobro.', 'ok')
    return redirect(url_for('mis_compras'))

@app.route('/mis-compras')
@login_required
def mis_compras():
    lista=list(pedidos.find({'usuario_id':ObjectId(session['usuario_id'])}).sort('fecha',-1))
    return render_template('mis_compras.html', pedidos=lista)

@app.route('/')
def inicio():
    q = request.args.get('q','').strip()
    categoria = request.args.get('categoria','').strip()
    filtro = {}
    if q: filtro['nombre']={'$regex':__import__('re').escape(q),'$options':'i'}
    if categoria: filtro['categoria']=categoria
    lista = list(juegos.find(filtro).sort('nombre',1))
    return render_template('index.html', juegos=lista, categorias=CATEGORIAS, q=q, categoria=categoria)

@app.route('/juego/<id>')
def detalle(id):
    return render_template('detalle.html', juego=buscar_juego(id))

@app.route('/registrar')
@admin_required
def registrar():
    return render_template('registrar.html', categorias=CATEGORIAS)

@app.route('/agregar',methods=['POST'])
@admin_required
def agregar():
    juegos.insert_one(leer_datos(request.form))
    return redirect(url_for('inicio'))

@app.route('/lista')
@admin_required
def lista():
    lista_juegos=list(juegos.find().sort('nombre',1))
    return render_template('lista.html',juegos=lista_juegos)

@app.route('/editar/<id>',methods=['GET','POST'])
@admin_required
def editar(id):
    juego=buscar_juego(id)
    if request.method=='POST':
        juegos.update_one({'_id':juego['_id']},{'$set':leer_datos(request.form)})
        return redirect(url_for('detalle',id=id))
    return render_template('editar.html',juego=juego,categorias=CATEGORIAS)

@app.route('/eliminar/<id>',methods=['POST'])
@admin_required
def eliminar(id):
    juego=buscar_juego(id)
    juegos.delete_one({'_id':juego['_id']})
    return redirect(url_for('lista'))

@app.route('/ayuda')
def ayuda():
    return render_template('ayuda.html',fecha=datetime.now().strftime('%d/%m/%Y'))

@app.route('/api/videojuegos',methods=['GET','POST'])
def api_videojuegos():
    if request.method=='GET':
        return jsonify([serializar(j) for j in juegos.find().sort('nombre',1)])
    datos=request.get_json(silent=True)
    if not isinstance(datos,dict): return jsonify(error='Envía un objeto JSON.'),400
    doc=leer_datos(datos)
    result=juegos.insert_one(doc)
    doc['_id']=result.inserted_id
    return jsonify(mensaje='Videojuego registrado correctamente',videojuego=serializar(doc)),201

@app.route('/api/videojuegos/<id>',methods=['GET','PUT','DELETE'])
def api_videojuego(id):
    juego=buscar_juego(id)
    if request.method=='GET': return jsonify(serializar(juego))
    if request.method=='DELETE':
        juegos.delete_one({'_id':juego['_id']})
        return jsonify(mensaje='Videojuego eliminado correctamente')
    datos=request.get_json(silent=True)
    if not isinstance(datos,dict): return jsonify(error='Envía un objeto JSON.'),400
    nuevo=leer_datos(datos)
    juegos.update_one({'_id':juego['_id']},{'$set':nuevo})
    nuevo['_id']=juego['_id']
    return jsonify(mensaje='Videojuego actualizado correctamente',videojuego=serializar(nuevo))

@app.errorhandler(PyMongoError)
def error_mongo(error):
    app.logger.error('Error al consultar MongoDB: %s',type(error).__name__)
    if request.path.startswith('/api/'):
        return jsonify(error='No fue posible conectar con MongoDB.'),503
    return render_template('error.html',mensaje='No fue posible conectar con MongoDB.'),503

@app.errorhandler(HTTPException)
def error_http(error):
    if request.path.startswith('/api/'):
        return jsonify(error=error.description),error.code
    return render_template('error.html',mensaje=error.description),error.code

if __name__=='__main__':
    app.run(host='127.0.0.1',port=5000,debug=False)

"""ERP para papelería de barrio - MVP (primera versión).

Módulos: seguridad/usuarios, productos y servicios, inventario (kardex),
proveedores, compras, ventas (punto de venta), clientes y crédito, caja y reportes.
Fuera de alcance (según el documento): contabilidad formal y facturación electrónica.
"""
import csv
import io
import os
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ERP_DB", os.path.join(BASE, "papeleria.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("ERP_SECRET", "cambiar-en-produccion")

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, usuario TEXT UNIQUE NOT NULL,
  clave_hash TEXT NOT NULL, rol TEXT NOT NULL CHECK(rol IN('admin','vendedor')),
  activo INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS productos(
  id INTEGER PRIMARY KEY, codigo TEXT UNIQUE, nombre TEXT NOT NULL, categoria TEXT,
  tipo TEXT NOT NULL DEFAULT 'producto' CHECK(tipo IN('producto','servicio')),
  costo REAL NOT NULL DEFAULT 0, precio REAL NOT NULL DEFAULT 0,
  stock REAL NOT NULL DEFAULT 0, stock_minimo REAL NOT NULL DEFAULT 0,
  activo INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS proveedores(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, telefono TEXT, notas TEXT,
  activo INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS clientes(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, telefono TEXT,
  activo INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS cajas(
  id INTEGER PRIMARY KEY, apertura TEXT NOT NULL, base REAL NOT NULL, usuario_id INTEGER,
  cierre TEXT, contado REAL, esperado REAL, diferencia REAL,
  estado TEXT NOT NULL DEFAULT 'abierta');
CREATE TABLE IF NOT EXISTS compras(
  id INTEGER PRIMARY KEY, fecha TEXT NOT NULL, proveedor_id INTEGER, total REAL NOT NULL,
  pagada_caja INTEGER NOT NULL DEFAULT 0, caja_id INTEGER, usuario_id INTEGER);
CREATE TABLE IF NOT EXISTS compra_items(
  id INTEGER PRIMARY KEY, compra_id INTEGER NOT NULL, producto_id INTEGER NOT NULL,
  cantidad REAL NOT NULL, costo REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ventas(
  id INTEGER PRIMARY KEY, fecha TEXT NOT NULL, cliente_id INTEGER,
  metodo TEXT NOT NULL CHECK(metodo IN('efectivo','credito')),
  total REAL NOT NULL, costo_total REAL NOT NULL, caja_id INTEGER, usuario_id INTEGER,
  anulada INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS venta_items(
  id INTEGER PRIMARY KEY, venta_id INTEGER NOT NULL, producto_id INTEGER NOT NULL,
  cantidad REAL NOT NULL, precio REAL NOT NULL, costo REAL NOT NULL);
CREATE TABLE IF NOT EXISTS abonos(
  id INTEGER PRIMARY KEY, fecha TEXT NOT NULL, cliente_id INTEGER NOT NULL,
  valor REAL NOT NULL, caja_id INTEGER, usuario_id INTEGER);
CREATE TABLE IF NOT EXISTS movimientos_caja(
  id INTEGER PRIMARY KEY, fecha TEXT NOT NULL, caja_id INTEGER NOT NULL,
  tipo TEXT NOT NULL CHECK(tipo IN('ingreso','egreso')), concepto TEXT NOT NULL,
  valor REAL NOT NULL, usuario_id INTEGER);
CREATE TABLE IF NOT EXISTS kardex(
  id INTEGER PRIMARY KEY, fecha TEXT NOT NULL, producto_id INTEGER NOT NULL,
  tipo TEXT NOT NULL, cantidad REAL NOT NULL, stock_resultante REAL NOT NULL,
  detalle TEXT, usuario_id INTEGER);
"""


# ----------------------------------------------------------------- base de datos
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if not db.execute("SELECT 1 FROM usuarios LIMIT 1").fetchone():
        db.execute(
            "INSERT INTO usuarios(nombre, usuario, clave_hash, rol) VALUES(?,?,?,?)",
            ("Propietario", "admin", generate_password_hash("admin123"), "admin"))
    db.commit()
    db.close()


def ahora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def num(v):
    try:
        return float(str(v).replace(",", ".").strip())
    except (TypeError, ValueError):
        return 0.0


@app.template_filter("money")
def money(v):
    return "$ " + f"{(v or 0):,.0f}".replace(",", ".")


@app.template_filter("qty")
def qty(v):
    return f"{(v or 0):g}"


SECCIONES = {
    "dashboard": "dashboard", "pos": "pos", "venta_guardar": "pos",
    "ventas": "ventas", "venta_detalle": "ventas", "venta_anular": "ventas",
    "productos": "productos", "producto_form": "productos", "kardex": "productos",
    "clientes": "clientes", "cliente_detalle": "clientes", "caja": "caja",
    "compras": "compras", "compra_nueva": "compras", "proveedores": "proveedores",
    "reportes": "reportes", "usuarios": "usuarios",
}
DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
         "septiembre", "octubre", "noviembre", "diciembre"]


@app.context_processor
def contexto():
    return {"tienda": os.environ.get("ERP_TIENDA", "Papelería"),
            "seccion": SECCIONES.get(request.endpoint)}


# ------------------------------------------------------------------- seguridad
def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("rol") != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper


@app.before_request
def guard():
    if request.endpoint in (None, "login", "static"):
        return None
    if "uid" not in session:
        return redirect(url_for("login"))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = get_db().execute("SELECT * FROM usuarios WHERE usuario=? AND activo=1",
                             (request.form["usuario"].strip(),)).fetchone()
        if u and check_password_hash(u["clave_hash"], request.form["clave"]):
            session.clear()
            session.update(uid=u["id"], rol=u["rol"], nombre=u["nombre"])
            return redirect(url_for("dashboard"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/usuarios", methods=["GET", "POST"])
@admin_required
def usuarios():
    db = get_db()
    if request.method == "POST":
        try:
            db.execute("INSERT INTO usuarios(nombre, usuario, clave_hash, rol) VALUES(?,?,?,?)",
                       (request.form["nombre"].strip(), request.form["usuario"].strip(),
                        generate_password_hash(request.form["clave"]), request.form["rol"]))
            db.commit()
            flash("Usuario creado.", "ok")
        except sqlite3.IntegrityError:
            flash("Ese nombre de usuario ya existe.", "error")
        return redirect(url_for("usuarios"))
    return render_template("usuarios.html", usuarios=db.execute(
        "SELECT * FROM usuarios ORDER BY nombre").fetchall())


@app.route("/usuarios/<int:uid>/toggle", methods=["POST"])
@admin_required
def usuario_toggle(uid):
    if uid == session["uid"]:
        flash("No puedes desactivar tu propio usuario.", "error")
    else:
        get_db().execute("UPDATE usuarios SET activo = 1 - activo WHERE id=?", (uid,))
        get_db().commit()
    return redirect(url_for("usuarios"))


@app.route("/usuarios/<int:uid>/clave", methods=["POST"])
@admin_required
def usuario_clave(uid):
    get_db().execute("UPDATE usuarios SET clave_hash=? WHERE id=?",
                     (generate_password_hash(request.form["clave"]), uid))
    get_db().commit()
    flash("Contraseña actualizada.", "ok")
    return redirect(url_for("usuarios"))


# ------------------------------------------------------------ inventario helpers
def mov_kardex(db, producto_id, tipo, cantidad, detalle):
    stock = db.execute("SELECT stock FROM productos WHERE id=?", (producto_id,)).fetchone()["stock"]
    db.execute("INSERT INTO kardex(fecha, producto_id, tipo, cantidad, stock_resultante, detalle, usuario_id)"
               " VALUES(?,?,?,?,?,?,?)",
               (ahora(), producto_id, tipo, cantidad, stock, detalle, session.get("uid")))


def caja_abierta():
    return get_db().execute("SELECT * FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1").fetchone()


def caja_esperado(db, c):
    def q(sql):
        return db.execute(sql, (c["id"],)).fetchone()[0] or 0
    return (c["base"]
            + q("SELECT SUM(total) FROM ventas WHERE caja_id=? AND metodo='efectivo' AND anulada=0")
            + q("SELECT SUM(valor) FROM abonos WHERE caja_id=?")
            + q("SELECT SUM(valor) FROM movimientos_caja WHERE caja_id=? AND tipo='ingreso'")
            - q("SELECT SUM(valor) FROM movimientos_caja WHERE caja_id=? AND tipo='egreso'")
            - q("SELECT SUM(total) FROM compras WHERE caja_id=? AND pagada_caja=1"))


# -------------------------------------------------------------------- dashboard
@app.route("/")
def dashboard():
    db = get_db()
    hoy = date.today()
    ventas_hoy = db.execute("SELECT COALESCE(SUM(total),0) t, COUNT(*) n FROM ventas "
                            "WHERE date(fecha)=? AND anulada=0", (hoy.isoformat(),)).fetchone()
    lista_hoy = db.execute(
        "SELECT v.id, v.fecha, v.metodo, v.total, v.anulada, c.nombre cliente FROM ventas v "
        "LEFT JOIN clientes c ON c.id=v.cliente_id WHERE date(v.fecha)=? ORDER BY v.id DESC LIMIT 12",
        (hoy.isoformat(),)).fetchall()
    bajos = db.execute("SELECT * FROM productos WHERE activo=1 AND tipo='producto' "
                       "AND stock <= stock_minimo ORDER BY stock LIMIT 6").fetchall()
    dias = [hoy - timedelta(days=i) for i in range(6, -1, -1)]
    totales = {r["d"]: r["t"] for r in db.execute(
        "SELECT date(fecha) d, SUM(total) t FROM ventas WHERE anulada=0 AND date(fecha) >= ? GROUP BY d",
        (dias[0].isoformat(),))}
    maximo = max([totales.get(d.isoformat(), 0) for d in dias] + [1])
    semana = [{"dia": DIAS[d.weekday()][:3], "total": totales.get(d.isoformat(), 0),
               "alto": round(100 * totales.get(d.isoformat(), 0) / maximo), "hoy": d == hoy}
              for d in dias]
    fecha_larga = f"{DIAS[hoy.weekday()]} {hoy.day} de {MESES[hoy.month - 1]}"
    return render_template("dashboard.html", ventas_hoy=ventas_hoy, lista_hoy=lista_hoy, bajos=bajos,
                           semana=semana, fecha_larga=fecha_larga,
                           cartera=cartera_total(db), caja=caja_abierta())


# --------------------------------------------------------------------- productos
@app.route("/productos")
def productos():
    q = request.args.get("q", "").strip()
    sql, params = "SELECT * FROM productos WHERE activo=1", []
    if q:
        sql += " AND (nombre LIKE ? OR codigo LIKE ? OR categoria LIKE ?)"
        params += [f"%{q}%"] * 3
    if request.args.get("bajos"):
        sql += " AND tipo='producto' AND stock <= stock_minimo"
    rows = get_db().execute(sql + " ORDER BY nombre", params).fetchall()
    return render_template("productos.html", productos=rows, q=q)


@app.route("/productos/nuevo", methods=["GET", "POST"])
@app.route("/productos/<int:pid>", methods=["GET", "POST"])
@admin_required
def producto_form(pid=None):
    db = get_db()
    p = db.execute("SELECT * FROM productos WHERE id=?", (pid,)).fetchone() if pid else None
    if pid and not p:
        abort(404)
    if request.method == "POST":
        f = request.form
        datos = (f["codigo"].strip() or None, f["nombre"].strip(), f["categoria"].strip(),
                 f["tipo"], num(f["costo"]), num(f["precio"]), num(f["stock_minimo"]))
        if datos[1] == "" or datos[5] < 0 or datos[4] < 0:
            flash("Nombre obligatorio y valores no negativos.", "error")
            return render_template("producto_form.html", p=p or f)
        try:
            if p:
                db.execute("UPDATE productos SET codigo=?, nombre=?, categoria=?, tipo=?, costo=?, "
                           "precio=?, stock_minimo=? WHERE id=?", (*datos, pid))
            else:
                cur = db.execute("INSERT INTO productos(codigo, nombre, categoria, tipo, costo, precio, "
                                 "stock_minimo, stock) VALUES(?,?,?,?,?,?,?,?)",
                                 (*datos, num(f.get("stock", 0)) if f["tipo"] == "producto" else 0))
                if f["tipo"] == "producto" and num(f.get("stock", 0)):
                    mov_kardex(db, cur.lastrowid, "inicial", num(f["stock"]), "Existencia inicial")
            db.commit()
        except sqlite3.IntegrityError:
            flash("Ya existe un producto con ese código.", "error")
            return render_template("producto_form.html", p=p or f)
        flash("Producto guardado.", "ok")
        return redirect(url_for("productos"))
    return render_template("producto_form.html", p=p)


@app.route("/productos/<int:pid>/eliminar", methods=["POST"])
@admin_required
def producto_eliminar(pid):
    get_db().execute("UPDATE productos SET activo=0 WHERE id=?", (pid,))
    get_db().commit()
    flash("Producto desactivado (el historial se conserva).", "ok")
    return redirect(url_for("productos"))


@app.route("/productos/<int:pid>/ajuste", methods=["POST"])
@admin_required
def producto_ajuste(pid):
    db = get_db()
    nuevo, motivo = num(request.form["stock"]), request.form["motivo"].strip()
    p = db.execute("SELECT * FROM productos WHERE id=? AND tipo='producto'", (pid,)).fetchone()
    if not p or not motivo or nuevo < 0:
        flash("Indica un stock válido y el motivo del ajuste.", "error")
    else:
        db.execute("UPDATE productos SET stock=? WHERE id=?", (nuevo, pid))
        mov_kardex(db, pid, "ajuste", nuevo - p["stock"], motivo)
        db.commit()
        flash("Inventario ajustado.", "ok")
    return redirect(url_for("kardex", pid=pid))


@app.route("/productos/<int:pid>/kardex")
@admin_required
def kardex(pid):
    db = get_db()
    p = db.execute("SELECT * FROM productos WHERE id=?", (pid,)).fetchone() or abort(404)
    movs = db.execute("SELECT * FROM kardex WHERE producto_id=? ORDER BY id DESC LIMIT 200", (pid,)).fetchall()
    return render_template("kardex.html", p=p, movs=movs)


# -------------------------------------------------------------------- proveedores
@app.route("/proveedores", methods=["GET", "POST"])
@admin_required
def proveedores():
    db = get_db()
    if request.method == "POST":
        f = request.form
        if f.get("id"):
            db.execute("UPDATE proveedores SET nombre=?, telefono=?, notas=? WHERE id=?",
                       (f["nombre"].strip(), f["telefono"].strip(), f["notas"].strip(), f["id"]))
        else:
            db.execute("INSERT INTO proveedores(nombre, telefono, notas) VALUES(?,?,?)",
                       (f["nombre"].strip(), f["telefono"].strip(), f["notas"].strip()))
        db.commit()
        return redirect(url_for("proveedores"))
    edit = db.execute("SELECT * FROM proveedores WHERE id=?", (request.args.get("edit"),)).fetchone()
    rows = db.execute("SELECT * FROM proveedores WHERE activo=1 ORDER BY nombre").fetchall()
    return render_template("proveedores.html", rows=rows, edit=edit)


@app.route("/proveedores/<int:pid>/eliminar", methods=["POST"])
@admin_required
def proveedor_eliminar(pid):
    get_db().execute("UPDATE proveedores SET activo=0 WHERE id=?", (pid,))
    get_db().commit()
    return redirect(url_for("proveedores"))


# ----------------------------------------------------------------------- compras
@app.route("/compras")
@admin_required
def compras():
    rows = get_db().execute(
        "SELECT c.*, p.nombre proveedor FROM compras c LEFT JOIN proveedores p ON p.id=c.proveedor_id "
        "ORDER BY c.id DESC LIMIT 100").fetchall()
    return render_template("compras.html", rows=rows)


@app.route("/compras/nueva", methods=["GET", "POST"])
@admin_required
def compra_nueva():
    db = get_db()
    if request.method == "POST":
        f = request.form
        items = [(int(pid), num(c), num(k)) for pid, c, k in
                 zip(f.getlist("producto_id"), f.getlist("cantidad"), f.getlist("costo"))
                 if pid and num(c) > 0]
        if not items or any(k < 0 for _, _, k in items):
            flash("Agrega al menos un producto con cantidad y costo válidos.", "error")
            return redirect(url_for("compra_nueva"))
        pagada = 1 if f.get("pagada_caja") else 0
        caja = caja_abierta()
        if pagada and not caja:
            flash("Para pagar con la caja debe haber una caja abierta.", "error")
            return redirect(url_for("compra_nueva"))
        total = sum(c * k for _, c, k in items)
        cur = db.execute("INSERT INTO compras(fecha, proveedor_id, total, pagada_caja, caja_id, usuario_id)"
                         " VALUES(?,?,?,?,?,?)",
                         (ahora(), f.get("proveedor_id") or None, total, pagada,
                          caja["id"] if pagada else None, session["uid"]))
        for pid, c, k in items:
            p = db.execute("SELECT * FROM productos WHERE id=?", (pid,)).fetchone()
            existencias = p["stock"] + c
            # costo promedio ponderado
            costo = (p["stock"] * p["costo"] + c * k) / existencias if p["stock"] > 0 else k
            db.execute("UPDATE productos SET stock=?, costo=? WHERE id=?", (existencias, costo, pid))
            db.execute("INSERT INTO compra_items(compra_id, producto_id, cantidad, costo) VALUES(?,?,?,?)",
                       (cur.lastrowid, pid, c, k))
            mov_kardex(db, pid, "compra", c, f"Compra #{cur.lastrowid}")
        db.commit()
        flash(f"Compra #{cur.lastrowid} registrada; el inventario se actualizó.", "ok")
        return redirect(url_for("compras"))
    return render_template(
        "compra_form.html",
        proveedores=db.execute("SELECT * FROM proveedores WHERE activo=1 ORDER BY nombre").fetchall(),
        productos=db.execute("SELECT id, nombre, costo FROM productos WHERE activo=1 AND tipo='producto' "
                             "ORDER BY nombre").fetchall())


# ------------------------------------------------------------------------ ventas
@app.route("/ventas")
def ventas():
    desde = request.args.get("fecha", date.today().isoformat())
    rows = get_db().execute(
        "SELECT v.*, c.nombre cliente, u.nombre vendedor FROM ventas v "
        "LEFT JOIN clientes c ON c.id=v.cliente_id LEFT JOIN usuarios u ON u.id=v.usuario_id "
        "WHERE date(v.fecha)=? ORDER BY v.id DESC", (desde,)).fetchall()
    return render_template("ventas.html", rows=rows, fecha=desde)


@app.route("/ventas/nueva")
def pos():
    db = get_db()
    if not caja_abierta():
        flash("Abre la caja antes de registrar ventas.", "error")
        return redirect(url_for("caja"))
    prods = [dict(r) for r in db.execute(
        "SELECT id, codigo, nombre, categoria, precio, stock, stock_minimo, tipo FROM productos "
        "WHERE activo=1 ORDER BY nombre")]
    clientes = db.execute("SELECT id, nombre FROM clientes WHERE activo=1 ORDER BY nombre").fetchall()
    return render_template("pos.html", productos=prods, clientes=clientes)


@app.route("/ventas/guardar", methods=["POST"])
def venta_guardar():
    db = get_db()
    data = request.get_json(force=True)
    caja = caja_abierta()
    if not caja:
        return jsonify(error="No hay caja abierta."), 400
    items, metodo = data.get("items", []), data.get("metodo", "efectivo")
    cliente_id = data.get("cliente_id") or None
    if not items:
        return jsonify(error="La venta no tiene productos."), 400
    if metodo == "credito" and not cliente_id:
        return jsonify(error="Una venta a crédito requiere un cliente."), 400
    lineas, total, costo_total = [], 0, 0
    for it in items:
        p = db.execute("SELECT * FROM productos WHERE id=? AND activo=1", (it["id"],)).fetchone()
        cant = num(it["cantidad"])
        if not p or cant <= 0:
            return jsonify(error="Producto o cantidad inválidos."), 400
        if p["tipo"] == "producto" and p["stock"] < cant:
            return jsonify(error=f"Stock insuficiente de «{p['nombre']}» (hay {p['stock']:g})."), 400
        # solo el propietario puede cambiar el precio en la venta
        precio = num(it.get("precio")) if session["rol"] == "admin" else p["precio"]
        if precio < 0:
            return jsonify(error="Precio inválido."), 400
        lineas.append((p, cant, precio))
        total += cant * precio
        costo_total += cant * p["costo"]
    cur = db.execute("INSERT INTO ventas(fecha, cliente_id, metodo, total, costo_total, caja_id, usuario_id)"
                     " VALUES(?,?,?,?,?,?,?)",
                     (ahora(), cliente_id, metodo, total, costo_total, caja["id"], session["uid"]))
    for p, cant, precio in lineas:
        db.execute("INSERT INTO venta_items(venta_id, producto_id, cantidad, precio, costo) VALUES(?,?,?,?,?)",
                   (cur.lastrowid, p["id"], cant, precio, p["costo"]))
        if p["tipo"] == "producto":
            db.execute("UPDATE productos SET stock = stock - ? WHERE id=?", (cant, p["id"]))
            mov_kardex(db, p["id"], "venta", -cant, f"Venta #{cur.lastrowid}")
    db.commit()
    return jsonify(ok=True, id=cur.lastrowid, url=url_for("venta_detalle", vid=cur.lastrowid))


@app.route("/ventas/<int:vid>")
def venta_detalle(vid):
    db = get_db()
    v = db.execute("SELECT v.*, c.nombre cliente, u.nombre vendedor FROM ventas v "
                   "LEFT JOIN clientes c ON c.id=v.cliente_id LEFT JOIN usuarios u ON u.id=v.usuario_id "
                   "WHERE v.id=?", (vid,)).fetchone() or abort(404)
    items = db.execute("SELECT i.*, p.nombre FROM venta_items i JOIN productos p ON p.id=i.producto_id "
                       "WHERE i.venta_id=?", (vid,)).fetchall()
    return render_template("venta_detalle.html", v=v, items=items)


@app.route("/ventas/<int:vid>/anular", methods=["POST"])
@admin_required
def venta_anular(vid):
    db = get_db()
    v = db.execute("SELECT * FROM ventas WHERE id=?", (vid,)).fetchone() or abort(404)
    if v["anulada"]:
        flash("La venta ya estaba anulada.", "error")
    else:
        for it in db.execute("SELECT i.*, p.tipo FROM venta_items i JOIN productos p ON p.id=i.producto_id "
                             "WHERE venta_id=?", (vid,)):
            if it["tipo"] == "producto":
                db.execute("UPDATE productos SET stock = stock + ? WHERE id=?", (it["cantidad"], it["producto_id"]))
                mov_kardex(db, it["producto_id"], "anulación", it["cantidad"], f"Anulación venta #{vid}")
        db.execute("UPDATE ventas SET anulada=1 WHERE id=?", (vid,))
        db.commit()
        flash(f"Venta #{vid} anulada y existencias devueltas.", "ok")
    return redirect(url_for("venta_detalle", vid=vid))


# --------------------------------------------------------------- clientes/crédito
def saldo_sql():
    return ("(COALESCE((SELECT SUM(total) FROM ventas WHERE cliente_id=c.id AND metodo='credito' AND anulada=0),0)"
            " - COALESCE((SELECT SUM(valor) FROM abonos WHERE cliente_id=c.id),0))")


def cartera_total(db):
    return db.execute(f"SELECT COALESCE(SUM(s),0) FROM (SELECT {saldo_sql()} s FROM clientes c)").fetchone()[0]


@app.route("/clientes", methods=["GET", "POST"])
def clientes():
    db = get_db()
    if request.method == "POST":
        db.execute("INSERT INTO clientes(nombre, telefono) VALUES(?,?)",
                   (request.form["nombre"].strip(), request.form["telefono"].strip()))
        db.commit()
        return redirect(url_for("clientes"))
    rows = db.execute(f"SELECT c.*, {saldo_sql()} saldo FROM clientes c WHERE c.activo=1 ORDER BY c.nombre").fetchall()
    return render_template("clientes.html", rows=rows)


@app.route("/clientes/<int:cid>", methods=["GET", "POST"])
def cliente_detalle(cid):
    db = get_db()
    c = db.execute(f"SELECT c.*, {saldo_sql()} saldo FROM clientes c WHERE c.id=?", (cid,)).fetchone() or abort(404)
    if request.method == "POST":
        valor, caja = num(request.form["valor"]), caja_abierta()
        if valor <= 0 or valor > c["saldo"]:
            flash("El abono debe ser mayor que 0 y no superar el saldo.", "error")
        elif not caja:
            flash("Abre la caja para registrar abonos.", "error")
        else:
            db.execute("INSERT INTO abonos(fecha, cliente_id, valor, caja_id, usuario_id) VALUES(?,?,?,?,?)",
                       (ahora(), cid, valor, caja["id"], session["uid"]))
            db.commit()
            flash("Abono registrado.", "ok")
        return redirect(url_for("cliente_detalle", cid=cid))
    cred = db.execute("SELECT * FROM ventas WHERE cliente_id=? AND metodo='credito' AND anulada=0 "
                      "ORDER BY id DESC", (cid,)).fetchall()
    abonos = db.execute("SELECT * FROM abonos WHERE cliente_id=? ORDER BY id DESC", (cid,)).fetchall()
    return render_template("cliente_detalle.html", c=c, cred=cred, abonos=abonos)


# -------------------------------------------------------------------------- caja
@app.route("/caja", methods=["GET", "POST"])
def caja():
    db = get_db()
    c = caja_abierta()
    if request.method == "POST":
        accion = request.form["accion"]
        if accion == "abrir" and not c:
            db.execute("INSERT INTO cajas(apertura, base, usuario_id) VALUES(?,?,?)",
                       (ahora(), num(request.form["base"]), session["uid"]))
            flash("Caja abierta.", "ok")
        elif accion == "movimiento" and c:
            valor = num(request.form["valor"])
            if valor > 0 and request.form["concepto"].strip():
                db.execute("INSERT INTO movimientos_caja(fecha, caja_id, tipo, concepto, valor, usuario_id)"
                           " VALUES(?,?,?,?,?,?)", (ahora(), c["id"], request.form["tipo"],
                                                    request.form["concepto"].strip(), valor, session["uid"]))
            else:
                flash("Indica concepto y un valor mayor que 0.", "error")
        elif accion == "cerrar" and c:
            esperado, contado = caja_esperado(db, c), num(request.form["contado"])
            db.execute("UPDATE cajas SET cierre=?, contado=?, esperado=?, diferencia=?, estado='cerrada' "
                       "WHERE id=?", (ahora(), contado, esperado, contado - esperado, c["id"]))
            flash(f"Caja cerrada. Diferencia: {money(contado - esperado)}", "ok")
        db.commit()
        return redirect(url_for("caja"))
    movs = db.execute("SELECT * FROM movimientos_caja WHERE caja_id=? ORDER BY id DESC",
                      (c["id"],)).fetchall() if c else []
    hist = db.execute("SELECT * FROM cajas WHERE estado='cerrada' ORDER BY id DESC LIMIT 15").fetchall()
    return render_template("caja.html", c=c, movs=movs, hist=hist,
                           esperado=caja_esperado(db, c) if c else 0)


# ---------------------------------------------------------------------- reportes
def rango():
    hoy = date.today()
    return (request.args.get("desde", hoy.replace(day=1).isoformat()),
            request.args.get("hasta", hoy.isoformat()))


@app.route("/reportes")
@admin_required
def reportes():
    db = get_db()
    desde, hasta = rango()
    r = db.execute("SELECT COALESCE(SUM(total),0) ventas, COALESCE(SUM(costo_total),0) costo, COUNT(*) n "
                   "FROM ventas WHERE anulada=0 AND date(fecha) BETWEEN ? AND ?", (desde, hasta)).fetchone()
    gastos = db.execute("SELECT COALESCE(SUM(m.valor),0) FROM movimientos_caja m WHERE m.tipo='egreso' "
                        "AND date(m.fecha) BETWEEN ? AND ?", (desde, hasta)).fetchone()[0]
    top = db.execute("SELECT p.nombre, SUM(i.cantidad) cant, SUM(i.cantidad*i.precio) total, "
                     "SUM(i.cantidad*(i.precio-i.costo)) utilidad FROM venta_items i "
                     "JOIN ventas v ON v.id=i.venta_id JOIN productos p ON p.id=i.producto_id "
                     "WHERE v.anulada=0 AND date(v.fecha) BETWEEN ? AND ? GROUP BY p.id "
                     "ORDER BY cant DESC LIMIT 10", (desde, hasta)).fetchall()
    por_dia = db.execute("SELECT date(fecha) dia, SUM(total) total, COUNT(*) n FROM ventas WHERE anulada=0 "
                         "AND date(fecha) BETWEEN ? AND ? GROUP BY dia ORDER BY dia", (desde, hasta)).fetchall()
    sin_rotacion = db.execute(
        "SELECT * FROM productos WHERE activo=1 AND tipo='producto' AND stock>0 AND id NOT IN ("
        "SELECT i.producto_id FROM venta_items i JOIN ventas v ON v.id=i.venta_id "
        "WHERE v.anulada=0 AND date(v.fecha) BETWEEN ? AND ?) ORDER BY stock*costo DESC LIMIT 10",
        (desde, hasta)).fetchall()
    valor_inv = db.execute("SELECT COALESCE(SUM(stock*costo),0) FROM productos WHERE activo=1 "
                           "AND tipo='producto'").fetchone()[0]
    return render_template("reportes.html", desde=desde, hasta=hasta, r=r, gastos=gastos, top=top,
                           por_dia=por_dia, sin_rotacion=sin_rotacion, valor_inv=valor_inv,
                           cartera=cartera_total(db))


@app.route("/reportes/ventas.csv")
@admin_required
def reporte_csv():
    desde, hasta = rango()
    rows = get_db().execute(
        "SELECT v.id, v.fecha, v.metodo, COALESCE(c.nombre,'') cliente, v.total, v.costo_total, "
        "v.total - v.costo_total utilidad FROM ventas v LEFT JOIN clientes c ON c.id=v.cliente_id "
        "WHERE v.anulada=0 AND date(v.fecha) BETWEEN ? AND ? ORDER BY v.id", (desde, hasta)).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["venta", "fecha", "metodo", "cliente", "total", "costo", "utilidad"])
    w.writerows([tuple(r) for r in rows])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=ventas_{desde}_{hasta}.csv"})


init_db()

if __name__ == "__main__":
    app.run(debug=True)

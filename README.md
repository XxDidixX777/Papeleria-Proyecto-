# ERP Papelería — MVP (primera versión)

Sistema sencillo y modular para una papelería de barrio. Implementa el alcance del proyecto de aula
(FT-INV-007): compras, inventario, ventas, crédito a clientes y control de caja.
**Fuera de alcance:** contabilidad formal y facturación electrónica.

## Ejecutar
```bash
pip install -r requirements.txt
python app.py          # abre http://127.0.0.1:5000
```
Usuario inicial: `admin` / `admin123` (cámbiala en *Usuarios*). La base de datos `papeleria.db` (SQLite) se crea sola.
Variables opcionales: `ERP_DB` (ruta de la BD), `ERP_SECRET` (clave de sesión; defínela en producción) y `ERP_TIENDA` (nombre de la papelería que se muestra en pantalla).
Ejemplo en Windows: `set ERP_TIENDA=Papelería El Lápiz` antes de `python app.py`.

## Módulos
| # | Módulo | Qué hace |
|---|--------|----------|
| 1 | Seguridad y usuarios | Login, roles *admin* (propietario) y *vendedor* |
| 2 | Productos y servicios | Catálogo, precios, costo, stock mínimo; fotocopias/impresiones como servicio |
| 3 | Inventario | Existencias, alertas de stock bajo, kardex, ajustes con motivo |
| 4 | Proveedores | Registro y consulta |
| 5 | Compras | Entrada de mercancía, actualiza stock y costo promedio |
| 6 | Ventas (POS) | Venta rápida por nombre o código de barras; descuenta stock; anulación |
| 7 | Clientes y crédito | Ventas fiadas, abonos, saldo por cliente |
| 8 | Caja | Apertura, ingresos/egresos, cierre con diferencia |
| 9 | Reportes | Ventas, utilidad, más vendidos, sin rotación, valor del inventario, cartera, CSV |

## Reglas de negocio implementadas
- Toda venta descuenta existencias y toda compra las aumenta (queda en el kardex).
- No se vende más de lo que hay en stock (los servicios no manejan stock).
- No se registran ventas, abonos ni pagos desde caja si la caja está cerrada.
- Una venta a crédito exige cliente; un abono no puede superar el saldo.
- Solo el propietario cambia precios, ve costos/utilidad, compra, anula ventas y ajusta inventario.
- Los productos no se borran, se desactivan (se conserva el historial).

## Pendiente / por validar con el propietario
Los supuestos del documento (descuentos, IVA, IDs de proveedores, fiado con plazos, múltiples cajas, respaldo de datos)
deben confirmarse en la etapa de validación antes de ampliar el sistema.

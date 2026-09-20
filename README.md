# Proyecto Final MIAD — Detección de tráfico de red malicioso

Prototipo de **tablero web** que clasifica tráfico de red (normal vs. tipos de
ataque) sobre el dataset **CIC-IDS2017**, construido sobre un análisis
enmarcado como **clasificación con desbalance de clases e interpretabilidad**.

> **¿Qué abrir según quién eres?**
> - **Quiero usar el tablero** → sección [Correr el tablero paso a paso](#correr-el-tablero-paso-a-paso) (o la URL pública, cuando esté desplegado)
> - **Jurado / lectura rápida** → [reports/informe_final.md](reports/informe_final.md) (informe resumido del análisis)
> - **Anexo técnico de experimentos** → [reports/reporte_tecnico_experimentos.pdf](reports/reporte_tecnico_experimentos.pdf) (reporte de implementación y experimentos, Módulo 2)
> - **Qué debe hacer el tablero** → [docs/especificacion_prototipo.md](docs/especificacion_prototipo.md) (los 22 requerimientos y las 6 pantallas)
> - **Verificar los requerimientos** → [tests/README.md](tests/README.md) y `python -m pytest -v`
> - **Reproducir el análisis desde los datos crudos** → sección [Reproducir el análisis](#reproducir-el-análisis)

## Datos

- **CIC-IDS2017** — Canadian Institute for Cybersecurity:
  https://www.unb.ca/cic/datasets/ids-2017.html. Cita requerida por su
  proveedor: Sharafaldin, Lashkari & Ghorbani (2018), ICISSP.
- Para reproducir el análisis, colocar los 8 CSV (`*.pcap_ISCX.csv`) en
  `data/raw/` (los datos no se versionan). **El tablero no los necesita.**

## Estructura

```
├── streamlit_app.py     el TABLERO — punto de entrada
├── app/                 núcleo del tablero: modelos, validación, pantallas
├── models/              los 3 modelos serializados + metadatos (1,3 MB)
├── tests/               pruebas de los 22 requerimientos (python -m pytest)
├── data/
│   ├── demo/            dos archivos de demostración (versionados)
│   └── raw/ interim/ processed/   datos del análisis (no se versionan)
├── docs/
│   ├── especificacion_prototipo.md   fuente de verdad del tablero
│   └── guia_proyecto.md              material de estudio del autor (no viaja a la entrega)
├── notebooks/           01_eda · 02_baseline · 03_desbalance ·
│                        04_interpretabilidad · 05_no_supervisado · 06_evaluacion_final
├── src/                 pipeline del análisis + modelo_final · preparar_demo
├── reports/
│   ├── informe_final.md                  informe resumido del análisis (entrega)
│   ├── reporte_tecnico_experimentos.pdf  anexo técnico de experimentos (entrega)
│   ├── reporte_tecnico_experimentos.tex  su fuente LaTeX (no viaja a la entrega)
│   ├── bitacora_proyecto.md              evidencia del proceso, fase por fase (no viaja)
│   ├── figures/                          las 17 figuras
│   └── resultados_fase3/ _fase4/ _final/ resultados numéricos en CSV
├── requirements.txt             entorno del TABLERO (liviano)
└── requirements-analisis.txt    entorno del ANÁLISIS (freeze completo)
```

## Entornos y dependencias (dos archivos, con una regla de oro)

- **`requirements.txt`** — el TABLERO (streamlit, scikit-learn, pandas,
  numpy, joblib, shap, pytest). Es lo que instala el hosting.
- **`requirements-analisis.txt`** — el entorno completo congelado del
  ANÁLISIS (notebooks y pipeline de `src/`).

> ⚠️ **Regla no negociable:** `scikit-learn` debe ser **idéntico en ambos
> archivos** (hoy: `1.9.0`) — de esa versión depende que los modelos de
> `models/` carguen. Si se actualiza en uno, se actualiza en el otro y se
> regeneran los modelos con `python -m src.modelo_final`.
>
> ⚠️ **Despliegue:** seleccionar **Python 3.13** en los ajustes avanzados del
> hosting (la misma versión con la que se congeló el entorno).

## Correr el tablero paso a paso

Procedimiento para **Windows**, desde cero, sin saber nada de Streamlit. Los
comandos se escriben en **PowerShell** (busca "PowerShell" en el menú Inicio)
y funcionan igual en el Símbolo del sistema. **No hace falta "activar" ningún
entorno**: se llama directamente al programa dentro de la carpeta del entorno,
que es la forma que no falla.

**1. Ir a la carpeta del proyecto.** Todo se ejecuta desde la raíz, la carpeta
que contiene `streamlit_app.py`:

```powershell
cd C:\Users\bryan\code\MIAD_ProyectoFinal
```

**2. Crear el entorno de la app (solo la primera vez).** Un "entorno" es una
copia aislada de Python con las versiones exactas que el tablero necesita. Se
crea con el Python instalado en la máquina (en esta, el de miniconda):

```powershell
C:\Users\bryan\miniconda3\python.exe -m venv .venv-app
.venv-app\Scripts\python.exe -m pip install -r requirements.txt
```

Tarda unos minutos y descarga ~300 MB. Si en tu máquina `python` sí está en
el PATH, la primera línea puede ser simplemente `python -m venv .venv-app`.

**3. Lanzar el tablero** (cada vez que quieras usarlo):

```powershell
.venv-app\Scripts\streamlit.exe run streamlit_app.py
```

**4. Abrir la URL** que aparece en la consola: normalmente
`http://localhost:8501`. La primera carga tarda unos segundos (carga los
modelos); las siguientes son instantáneas. La consola debe quedarse abierta
mientras uses el tablero.

**5. Detenerlo:** en la consola, pulsa `Ctrl + C`. El servidor solo muere con
`Ctrl + C` o al cerrar la consola; cerrar la pestaña del navegador no lo
detiene.

### Si algo falla

| Síntoma | Causa | Solución |
|---|---|---|
| `'streamlit' is not recognized…` o `No module named streamlit` | Se llamó a `streamlit` "a secas": el Python del sistema no lo tiene; solo el del entorno. | Usa la ruta completa como en el paso 3: `.venv-app\Scripts\streamlit.exe run streamlit_app.py`. Si la carpeta `.venv-app` no existe, vuelve al paso 2. |
| `Python was not found; run without arguments to install from the Microsoft Store` | `python` no está en el PATH de esta máquina (el alias de la tienda lo intercepta). | En el paso 2 usa la ruta completa del intérprete (`C:\Users\bryan\miniconda3\python.exe`). |
| `Error: Invalid value: File does not exist: streamlit_app.py` | Estás en la carpeta equivocada. | `cd` a la raíz del proyecto (paso 1) y vuelve a lanzar. |
| La consola dice `http://localhost:8502` (u otro número distinto de 8501) | **Ya tienes otro tablero corriendo** en el 8501 (otra consola abierta). Streamlit no avisa: salta al siguiente puerto en silencio. | Usa la URL que te muestra **esta** consola, o cierra la otra instancia (`Ctrl + C` en su consola) y relanza. Dos instancias con código distinto dan resultados confusos. |
| Error raro (`KeyError`, pantalla a medias) en una pestaña que abriste hace días | Es una **pestaña vieja** apuntando a un servidor que ya no existe o que quedó con código antiguo en memoria. | Cierra esa pestaña, detén cualquier tablero abierto (`Ctrl + C`), relanza y abre la URL nueva. Recargar la página **no** basta si el servidor es viejo. |
| Prefieres "activar" el entorno y `Activate.ps1` da `running scripts is disabled` | La política de PowerShell bloquea los scripts `.ps1`; y `activate.bat` **no funciona en PowerShell** (solo en cmd). | No hace falta activar: usa las rutas directas de estas instrucciones. Si insistes: `Set-ExecutionPolicy -Scope Process Bypass` y luego `.\.venv-app\Scripts\Activate.ps1`. |
| Advertencia amarilla al abrir: "Los modelos se guardaron con scikit-learn X y este servidor ejecuta Y" | El entorno tiene otra versión de scikit-learn. | Reinstala exactamente `requirements.txt` en `.venv-app` (paso 2, segunda línea). |
| Cambiaste código en `app/` o `models/` y no se ven los cambios | El servidor guarda los modelos en memoria y no los recarga solo. | Detén el tablero (`Ctrl + C`) y relánzalo. |

## Cómo consumir el proyecto (tres niveles)

1. **Usar el tablero y leer** (no requiere datos). Lanza el tablero y prueba
   con los dos archivos de demostración de la barra lateral; los notebooks se
   entregan **ya ejecutados**, con tablas y figuras embebidas, y los informes
   contienen los mismos resultados.
2. **Verificar y re-ejecutar lo ligero.** `python -m pytest -v` corre las
   pruebas de los 22 requerimientos en ~10 s; los notebooks `03` a `06` leen
   únicamente los CSVs de `reports/resultados_*/` y corren en segundos.
3. **Reproducción completa desde los CSV crudos** (opcional; requiere ~8 GB de
   RAM y descargar el dataset): ver la sección siguiente.

## Pruebas de los requerimientos

Desde la raíz, con el entorno de la app activo:

```bash
python -m pytest -v
```

Cada prueba verifica un requerimiento (R1–R22) siguiendo su "prueba
prevista"; 19 son automáticas y 6 se documentan como manuales (dependen del
despliegue o de una persona ajena) y aparecen como omitidas con su razón.
Detalle en [tests/README.md](tests/README.md).

## Reproducir el análisis

Requiere el entorno completo del análisis (distinto al de la app):

```powershell
C:\Users\bryan\miniconda3\python.exe -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-analisis.txt
```

Los pasos se lanzan con el Python de ese entorno, en este orden
(`.venv\Scripts\python.exe -m src.preparacion`, etc.; abajo abreviado como
`python`):

```bash
python -m src.preparacion        # 1. consolida los 8 CSV                (~3 min)
python -m src.limpieza           # 2. aplica la limpieza aprobada        (~2 min)
python -m src.split              # 3. split 80/20 único (se niega a repetirse)
python -m src.experimentos       # 4. matriz de desbalance (Fase 3)      (~40-90 min*)
python -m src.resultados         # 5. condensa la Fase 3 a CSVs          (~1 min)
python -m src.interpretabilidad  # 6. pregunta 1 + experimento del puerto (~15 min*)
python -m src.no_supervisado     # 7. pregunta 3 (Isolation Forest/LOF)  (~10 min*)
python -m src.evaluacion_final   # 8. ÚNICA evaluación sobre el test     (~2 min*)
python -m src.modelo_final       # 9. serializa los modelos del tablero  (~1 min)
python -m src.preparar_demo      # 10. genera los archivos de demo       (~1 min)
```

> El paso 8 se ejecutó **una sola vez** (regla del proyecto) y su checkpoint
> impide recalcularlo por accidente.

\* Tiempos medidos en una máquina de 24 núcleos y 32 GB de RAM; en un equipo
modesto pueden tomar varias horas en total. Son cómputos de **una sola vez**,
checkpointeados: si se interrumpen, al relanzar no repiten lo ya calculado.
Los notebooks se ejecutan en orden (`01_eda` → `06_evaluacion_final`) con
`jupyter lab` desde el entorno de análisis activo: **`01` y `02` requieren los
datos locales** (pasos 1-3; `02` re-entrena sus líneas base, ~15 min);
**`03` a `06` leen los CSVs versionados** y corren en segundos.

## Reproducibilidad

`RANDOM_STATE = 42` en todo el proyecto; el conjunto de prueba se aparta una
sola vez y se evaluó una única vez; todo remuestreo ocurre dentro de
pipelines de `imblearn` durante la validación cruzada. Las pruebas R7 y R8 lo
verifican por código.

# Proyecto Final MIAD — Detección de tráfico de red malicioso (CIC-IDS2017)

## Contexto
Tesis de la Maestría en Inteligencia Analítica de Datos (ciencia de datos, NO
ciberseguridad). El jurado son científicos de datos, no expertos en seguridad:
priorizar claridad, interpretabilidad y explicaciones sencillas. Todo término
de ciberseguridad debe explicarse en lenguaje llano. El problema se enmarca como
un problema de CLASIFICACIÓN con desbalance de clases e interpretabilidad, no
como un problema de seguridad ofensiva.

## Datos
- Dataset: CIC-IDS2017 (Canadian Institute for Cybersecurity).
- Formato: varios CSV (uno por día/ataque), ~80 features de flujo generadas con
  CICFlowMeter, más una columna de etiqueta (`Label`).
- Ubicación: `data/raw/` (grande, gitignored). CONFIRMA la ruta y lista los
  archivos reales antes de asumir nada. Nunca hardcodear nombres de archivo.

## Trampas conocidas de CIC-IDS2017 (inspeccionar el archivo real, NO asumir)
- Nombres de columna con ESPACIOS al inicio (ej. ` Label`). Normalizar con strip.
- Valores Inf y NaN en `Flow Bytes/s` y `Flow Packets/s`.
- Valores negativos en features como `Flow Duration`.
- Filas duplicadas.
- Desbalance severo: BENIGN domina; clases como Heartbleed tienen ~11 casos.
- Errores de etiquetado documentados en la literatura (mencionar como limitación
  en el informe; ver README).

## Convenciones
- Datos crudos en `data/raw/`; intermedios en `data/interim/`; procesados en
  `data/processed/` como Parquet con dtypes downcasteados (float32). Nunca
  commitear datos.
- Notebooks numerados (`01_eda.ipynb`, `02_...`); la lógica reutilizable va en
  `src/` como módulos, no repetida en notebooks.
- Reproducibilidad total: seeds fijos (usar una constante RANDOM_STATE = 42),
  y dependencias en `requirements.txt`.
- El entregable debe correr desde un ZIP SIN servicios externos: solo pandas y
  el entorno virtual. NADA de Docker/Postgres en el pipeline calificado.
- Documentación, comentarios, nombres de secciones y gráficas en español.

## Flujo de trabajo (IMPORTANTE)
- Trabajar por FASES y DETENERSE para revisión entre cada una.
- NO construir modelos hasta que el EDA y las preguntas de negocio estén aprobados.
- Antes de escribir pipeline, inspeccionar los datos reales (schema, dtypes,
  distribución de clases, calidad).
- Ante cualquier ambigüedad, preguntar en vez de asumir.

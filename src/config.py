"""Configuración central del proyecto.

Todas las rutas y constantes compartidas viven aquí para que los notebooks
y scripts no las repitan ni las hardcodeen.
"""

from pathlib import Path

# Raíz del proyecto (carpeta que contiene src/, data/, notebooks/, ...)
RAIZ_PROYECTO = Path(__file__).resolve().parent.parent

RUTA_DATOS = RAIZ_PROYECTO / "data"
RUTA_RAW = RUTA_DATOS / "raw"
RUTA_INTERIM = RUTA_DATOS / "interim"
RUTA_PROCESSED = RUTA_DATOS / "processed"
RUTA_REPORTES = RAIZ_PROYECTO / "reports"
RUTA_FIGURAS = RUTA_REPORTES / "figures"

# Semilla única para todo el proyecto (reproducibilidad total)
RANDOM_STATE = 42

# Nombre de la columna objetivo DESPUÉS de normalizar los nombres de columna
COLUMNA_ETIQUETA = "Label"
ETIQUETA_BENIGNA = "BENIGN"

# Archivo consolidado que produce la fase de preparación
ARCHIVO_CONSOLIDADO = RUTA_PROCESSED / "cicids2017_consolidado.parquet"

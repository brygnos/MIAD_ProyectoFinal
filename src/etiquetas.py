"""Etiquetas derivadas para cada pregunta de negocio — Fase 2.

Dos vistas del mismo dataset:

- **Binaria (preguntas 1 y 3):** Normal (0) vs Ataque (1). TODAS las filas
  participan, incluidas las clases ultra-raras.
- **Multiclase (pregunta 2):** el tipo de ataque. Decisiones documentadas:
  * Los 3 ataques web (Brute Force, XSS, Sql Injection) se agrupan en la
    familia "Web Attack": por separado son demasiado pequeños (1.470/652/21
    casos tras limpieza) y pertenecen al mismo dominio (ataques a la
    aplicación web). En consecuencia, "SQL Injection" no existe como clase
    propia del multiclase: sus casos quedan dentro de la familia.
  * Heartbleed (11 casos) e Infiltration (36) quedan FUERA del multiclase:
    con validación cruzada de 5 particiones aportarían ~2-7 casos por
    partición y cualquier métrica por clase sería ruido. Sus filas se
    excluyen del entrenamiento multiclase, pero SÍ cuentan en la vista
    binaria (¿al menos se detectan como "ataque"?), que es donde se
    reportan como limitación.
"""

import pandas as pd

from src.config import ETIQUETA_BENIGNA

NOMBRE_NORMAL = "Normal"
NOMBRE_ATAQUE = "Ataque"

FAMILIA_WEB = "Web Attack"
CLASES_WEB = [
    "Web Attack - Brute Force",
    "Web Attack - XSS",
    "Web Attack - Sql Injection",
]

# Clases sin datos suficientes para métricas por clase (ver docstring)
CLASES_EXCLUIDAS_MULTICLASE = ["Heartbleed", "Infiltration"]


def etiqueta_binaria(labels: pd.Series) -> pd.Series:
    """1 = ataque, 0 = tráfico normal (int8, para las preguntas 1 y 3)."""
    return (labels != ETIQUETA_BENIGNA).astype("int8").rename("es_ataque")


def mascara_multiclase(labels: pd.Series) -> pd.Series:
    """True en las filas que participan del problema multiclase (pregunta 2)."""
    return ~labels.isin(CLASES_EXCLUIDAS_MULTICLASE)


def etiqueta_multiclase(labels: pd.Series) -> pd.Series:
    """Tipo de tráfico con los ataques web agrupados en su familia.

    Aplicar junto con `mascara_multiclase` para excluir las clases sin datos
    suficientes; aquí se valida que no vengan incluidas.
    """
    if labels.isin(CLASES_EXCLUIDAS_MULTICLASE).any():
        raise ValueError(
            "La serie contiene clases excluidas del multiclase; "
            "filtrar antes con mascara_multiclase()."
        )
    return (
        labels.astype(str)
        .replace(dict.fromkeys(CLASES_WEB, FAMILIA_WEB))
        .astype("category")
        .rename("tipo_trafico")
    )

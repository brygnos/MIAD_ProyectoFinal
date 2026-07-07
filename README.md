# Proyecto Final MIAD — Detección de tráfico de red malicioso

Detección de intrusiones/anomalías de red mediante técnicas de analítica y
aprendizaje de máquina sobre el dataset **CIC-IDS2017**. Enmarcado como un
problema de **clasificación con desbalance de clases e interpretabilidad**.

Ver link aquí a base de datos: https://www.unb.ca/cic/datasets/ids-2017.html

> Estado: en fase de exploración de datos y definición de preguntas de negocio.

---

## Preguntas de negocio (a confirmar tras el EDA)

Se definirán con base en lo que los datos realmente soporten. Candidatas:

1. **Interpretabilidad** — ¿Qué características del tráfico distinguen un ataque
   del tráfico normal, y cuáles son las más informativas?
2. **Desbalance / clases raras** — ¿Qué tan bien se clasifica el *tipo* de ataque,
   incluyendo los poco frecuentes, y qué técnicas de manejo de desbalance mejoran
   esa detección?
3. **No supervisado** — ¿Un modelo entrenado solo con tráfico normal puede detectar
   ataques que nunca vio etiquetados?

*(Actualizar esta sección con las preguntas finales después del EDA.)*

---

## Dataset

- **CIC-IDS2017** — Canadian Institute for Cybersecurity (University of New Brunswick).
- ~2.83M flujos, ~80 features de flujo (CICFlowMeter) + etiqueta, tráfico benigno
  y varios ataques (brute force, DoS/DDoS, web, infiltración, botnet, port scan)
  a lo largo de 5 días.
- Descarga: https://www.unb.ca/cic/datasets/ids-2017.html
- **Ubicación esperada:** colocar los CSV en `data/raw/` (ignorados por git).

### Limitaciones conocidas (documentar en el informe)
El dataset original tiene problemas de calidad reportados en la literatura
(Engelen 2021; Lanvin 2022/2023; Rosay 2022): errores de etiquetado, ataques
no etiquetados, miscálculo de features, paquetes desordenados/duplicados,
valores negativos e Inf/NaN, y desbalance severo. El pipeline los aborda en la
fase de limpieza; existen versiones corregidas (ej. LYCOS-IDS2017) que pueden
usarse como comparación.

---

## Estructura del proyecto

```
MIAD_ProyectoFinal/
├── CLAUDE.md            # Instrucciones para Claude Code (contexto del proyecto)
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   ├── raw/             # CSV originales de CIC-IDS2017 (gitignored)
│   ├── interim/         # datos limpios/unidos intermedios (gitignored)
│   └── processed/       # dataset final en Parquet, listo para modelar (gitignored)
├── notebooks/           # 01_eda.ipynb, 02_preprocessing.ipynb, ...
├── src/                 # funciones reutilizables (carga, limpieza, features, modelos)
└── reports/
    └── figures/         # gráficas exportadas para el informe
```

---

## Setup

```bash
# 1. Crear entorno virtual
python -m venv .venv

# 2. Activar
#   Windows (PowerShell):  .venv\Scripts\Activate.ps1
#   WSL / Linux / macOS:   source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Registrar el kernel para Jupyter
python -m ipykernel install --user --name miad-proyecto
```

> Para reproducibilidad final, una vez el entorno funcione, congelar versiones
> exactas: `pip freeze > requirements.txt`.

---

## Cómo correr (por fases)

1. **Fase 0-1 — Exploración y preguntas de negocio.** Colocar los CSV en
   `data/raw/`, ejecutar el EDA (`notebooks/01_eda.ipynb`) y producir
   `preguntas_de_negocio.md`.
2. **Fase 2 — Preprocesamiento.** Limpieza (Inf/NaN, negativos, duplicados,
   nombres de columna), consolidación a Parquet en `data/processed/`.
3. **Fase 3 — Modelado.** Entrenamiento de modelos supervisados/no supervisados
   según las preguntas definidas.
4. **Fase 4 — Evaluación.** Métricas honestas (con desbalance), interpretabilidad,
   gráficas para el informe.

---

## Reproducibilidad
- `RANDOM_STATE = 42` en todo el proyecto.
- Los datos no se versionan (ver `.gitignore`); descargar de la fuente oficial.

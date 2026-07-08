# Proyecto Final MIAD — Detección de tráfico de red malicioso

Clasificación de tráfico de red (normal vs tipos de ataque) sobre el dataset
**CIC-IDS2017**, enmarcada como un problema de **clasificación con desbalance
de clases e interpretabilidad**.

> 📄 **La fuente de verdad del proyecto es el informe vivo:
> [reports/informe.md](reports/informe.md)** (hallazgos, decisiones, métricas
> y limitaciones, fase por fase). Las preguntas de negocio y su evaluación
> están en [preguntas_de_negocio.md](preguntas_de_negocio.md).

## Datos

- **CIC-IDS2017** — Canadian Institute for Cybersecurity:
  https://www.unb.ca/cic/datasets/ids-2017.html
- Colocar los 8 CSV (`*.pcap_ISCX.csv`) en `data/raw/` (los datos no se
  versionan).

## Estructura

```
├── data/            raw/ (CSV originales) · interim/ · processed/ (gitignored)
├── notebooks/       01_eda · 02_baseline · 03_desbalance
├── src/             config · carga · calidad · preparacion · limpieza ·
│                    split · features · etiquetas · experimentos · resultados
└── reports/         informe.md (informe vivo) · figures/ · resultados_fase3/
```

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m ipykernel install --user --name miad-proyecto
```

## Cómo consumir el proyecto (tres niveles)

1. **Leer (no requiere correr nada).** Los notebooks se entregan **ya
   ejecutados**, con tablas y figuras embebidas, y el informe
   ([reports/informe.md](reports/informe.md)) contiene los mismos resultados.
2. **Re-ejecutar los análisis ligeros.** `03_desbalance.ipynb` lee únicamente
   los CSVs de `reports/resultados_fase3/` (kilobytes, incluidos en el repo):
   corre en segundos en cualquier equipo.
3. **Reproducción completa desde los CSV crudos** (opcional; requiere ~8 GB de
   RAM y descargar el dataset):

```bash
python -m src.preparacion    # 1. consolida los 8 CSV            (~3 min)
python -m src.limpieza       # 2. aplica la limpieza aprobada    (~2 min)
python -m src.split          # 3. split 80/20 único (se niega a repetirse)
python -m src.experimentos   # 4. matriz de desbalance (Fase 3)  (~40-90 min*)
python -m src.resultados     # 5. condensa resultados a CSVs     (~1 min)
```

\* Tiempos medidos en una máquina de 24 núcleos y 32 GB de RAM; en un equipo
modesto el paso 4 puede tomar varias horas. Es un cómputo de **una sola vez**:
sus resultados quedan guardados y los notebooks no lo repiten. Los notebooks
(`01_eda`, `02_baseline`, `03_desbalance`) se ejecutan en ese orden con el
kernel del entorno; `02_baseline` re-entrena sus líneas base (~15 min).

## Reproducibilidad

`RANDOM_STATE = 42` en todo el proyecto; el conjunto de prueba se aparta una
sola vez y no se toca hasta la evaluación final; todo remuestreo ocurre dentro
de pipelines de `imblearn` durante la validación cruzada.

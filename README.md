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
├── docs/            guia_proyecto.md (material de estudio del autor; NO es
│                    parte del informe de entrega)
├── notebooks/       01_eda · 02_baseline · 03_desbalance ·
│                    04_interpretabilidad · 05_no_supervisado ·
│                    06_evaluacion_final
├── src/             config · carga · calidad · preparacion · limpieza ·
│                    split · features · etiquetas · experimentos · resultados ·
│                    interpretabilidad · no_supervisado · evaluacion_final
└── reports/         informe.md (trabajo) · informe_final.md (entrega) ·
                     figures/ · resultados_fase3/ · resultados_fase4/ ·
                     resultados_final/
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
python -m src.preparacion        # 1. consolida los 8 CSV                (~3 min)
python -m src.limpieza           # 2. aplica la limpieza aprobada        (~2 min)
python -m src.split              # 3. split 80/20 único (se niega a repetirse)
python -m src.experimentos       # 4. matriz de desbalance (Fase 3)      (~40-90 min*)
python -m src.resultados         # 5. condensa la Fase 3 a CSVs          (~1 min)
python -m src.interpretabilidad  # 6. pregunta 1 + experimento del puerto (~15 min*)
python -m src.no_supervisado     # 7. pregunta 3 (Isolation Forest/LOF)  (~10 min*)
python -m src.evaluacion_final   # 8. ÚNICA evaluación sobre el test     (~2 min*)
```

> El paso 8 se ejecutó **una sola vez** (regla del proyecto) y su checkpoint
> impide recalcularlo por accidente. El informe de entrega es
> [reports/informe_final.md](reports/informe_final.md).

\* Tiempos medidos en una máquina de 24 núcleos y 32 GB de RAM; en un equipo
modesto los pasos marcados pueden tomar varias horas en total. Son cómputos de
**una sola vez**, checkpointeados: si se interrumpen, al relanzar no repiten lo
ya calculado, y los notebooks no los repiten jamás. Los notebooks (`01_eda`,
`02_baseline`, `03_desbalance`, `04_interpretabilidad`, `05_no_supervisado`,
`06_evaluacion_final`) se ejecutan en ese orden con el kernel del entorno; `02_baseline` re-entrena sus
líneas base (~15 min), los demás leen resultados guardados y corren en
segundos.

## Reproducibilidad

`RANDOM_STATE = 42` en todo el proyecto; el conjunto de prueba se aparta una
sola vez y no se toca hasta la evaluación final; todo remuestreo ocurre dentro
de pipelines de `imblearn` durante la validación cruzada.

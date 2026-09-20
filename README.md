# Proyecto Final MIAD — Detección de tráfico de red malicioso

Clasificación de tráfico de red (normal vs tipos de ataque) sobre el dataset
**CIC-IDS2017**, enmarcada como un problema de **clasificación con desbalance
de clases e interpretabilidad**.

> **¿Qué leer según quién eres?**
> - **Jurado / lectura rápida** → [reports/informe_final.md](reports/informe_final.md) (informe resumido, la entrega)
> - **Todo el detalle y las justificaciones** → [reports/informe.md](reports/informe.md) (informe detallado, fase por fase)
> - **Reproducir o re-ejecutar** → este README (sección "Cómo consumir el proyecto")
> - **Estudiar y defender el proyecto** → [docs/guia_proyecto.md](docs/guia_proyecto.md) (material de estudio del autor)

## Datos

- **CIC-IDS2017** — Canadian Institute for Cybersecurity:
  https://www.unb.ca/cic/datasets/ids-2017.html
- Colocar los 8 CSV (`*.pcap_ISCX.csv`) en `data/raw/` (los datos no se
  versionan).

## Estructura

```
├── streamlit_app.py el TABLERO (prototipo web) — punto de entrada
├── app/             núcleo del tablero: modelos, validación, pantallas
├── models/          modelos serializados + metadatos (los usa el tablero)
├── data/            raw/ · interim/ · processed/ (gitignored) · demo/ (los
│                    dos archivos de demostración, versionados)
├── docs/            especificacion_prototipo.md (fuente de verdad del
│                    tablero) · notas_equipo.md · guia_proyecto.md (estudio)
├── notebooks/       01_eda · 02_baseline · 03_desbalance ·
│                    04_interpretabilidad · 05_no_supervisado ·
│                    06_evaluacion_final
├── src/             pipeline del análisis (preparacion → limpieza → split →
│                    experimentos → …) + modelo_final · preparar_demo
└── reports/         informe.md (detallado) · informe_final.md (resumido) ·
                     figures/ · resultados_fase3/ · _fase4/ · _final/
```

## Entornos y dependencias (dos archivos, con una regla de oro)

- **`requirements.txt`** — el TABLERO (liviano: streamlit, scikit-learn,
  pandas, numpy, joblib, shap). Es lo que instala el hosting.
- **`requirements-analisis.txt`** — el entorno completo congelado del
  ANÁLISIS (notebooks y pipeline de `src/`).

> ⚠️ **Regla no negociable:** `scikit-learn` debe ser **idéntico en ambos
> archivos** (hoy: `1.9.0`) — de esa versión depende que los modelos de
> `models/` carguen. Si se actualiza en uno, se actualiza en el otro y se
> regeneran los modelos con `python -m src.modelo_final`.
>
> ⚠️ **Despliegue:** seleccionar **Python 3.13** en los ajustes avanzados del
> hosting (la misma versión con la que se congeló el entorno). Desplegar en
> otra versión de Python puede romper la carga de los modelos.

### Correr el tablero localmente

```bash
python -m venv .venv-app
# Windows: .venv-app\Scripts\Activate.ps1  |  Linux/macOS: source .venv-app/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Se abre en el navegador (http://localhost:8501) con dos archivos de
demostración listos en la barra lateral.

### Reproducir el análisis

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements-analisis.txt
jupyter lab   # lanzarlo desde el venv activo: los notebooks usan su kernel por defecto
```

## Cómo consumir el proyecto (tres niveles)

1. **Leer (no requiere correr nada).** Los notebooks se entregan **ya
   ejecutados**, con tablas y figuras embebidas, y los dos informes
   (resumido y detallado) contienen los mismos resultados.
2. **Re-ejecutar los análisis ligeros.** Los notebooks `03` a `06` leen
   únicamente los CSVs de `reports/resultados_*/` (kilobytes, versionados con
   el repo): corren en segundos en cualquier equipo, sin re-entrenar nada.
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
python -m src.modelo_final       # 9. serializa los modelos del tablero  (~1 min)
python -m src.preparar_demo      # 10. genera los archivos de demo       (~1 min)
```

> El paso 8 se ejecutó **una sola vez** (regla del proyecto) y su checkpoint
> impide recalcularlo por accidente. El informe de entrega es
> [reports/informe_final.md](reports/informe_final.md).

\* Tiempos medidos en una máquina de 24 núcleos y 32 GB de RAM; en un equipo
modesto los pasos marcados pueden tomar varias horas en total. Son cómputos de
**una sola vez**, checkpointeados: si se interrumpen, al relanzar no repiten lo
ya calculado, y los notebooks no los repiten jamás. Los notebooks se ejecutan
en orden (`01_eda` → `06_evaluacion_final`): **`01` y `02` requieren los datos
locales** (haber corrido los pasos 1-3; `02` re-entrena sus líneas base,
~15 min), mientras que **`03` a `06` leen los CSVs versionados** y corren en
segundos en cualquier equipo.

## Reproducibilidad

`RANDOM_STATE = 42` en todo el proyecto; el conjunto de prueba se aparta una
sola vez y no se toca hasta la evaluación final; todo remuestreo ocurre dentro
de pipelines de `imblearn` durante la validación cruzada.

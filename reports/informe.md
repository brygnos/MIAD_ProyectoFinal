# Informe — Detección de tráfico de red malicioso (CIC-IDS2017)

> **Documento vivo.** Fuente de verdad del proyecto: se actualiza al cierre de
> cada fase, agregando (nunca borrando) lo anterior. El README solo enlaza aquí.
>
> Proyecto de tesis — Maestría en Inteligencia Analítica de Datos. El problema
> se aborda como **clasificación con desbalance de clases e interpretabilidad**;
> los términos de ciberseguridad se explican en lenguaje llano.

---

## Fase 0-1 — Exploración de datos y preguntas de negocio

### Qué son los datos

CIC-IDS2017 simula **una semana de tráfico** (lunes-viernes) en una red
corporativa. Cada fila es un **flujo de red** —una "conversación" entre dos
computadores— resumida en ~77 medidas numéricas (paquetes, tamaños, ritmos,
duración). La columna `Label` indica tráfico normal (`BENIGN`) o uno de 14
tipos de ataque. Los 8 CSV crudos (~846 MB) tienen schema idéntico.

### Hallazgos del EDA (`notebooks/01_eda.ipynb`)

**Trampas del formato, verificadas en los archivos reales:**
- 65 de 79 nombres de columna traen espacios al inicio (` Flow Duration`).
- `Fwd Header Length` viene **dos veces** en los 8 archivos (copia exacta,
  verificado antes de eliminar la repetida).
- Las etiquetas de ataques web traen un carácter dañado en el CSV original
  (`Web Attack � Brute Force`); se normalizó a guion ASCII.

**Consolidación** (`src/preparacion.py`): 2.830.743 flujos, 79 columnas;
memoria 1.834 MB → 664 MB con float32; Parquet de 255 MB.

**Desbalance severo en dos niveles** (figura
`reports/figures/01_distribucion_clases.png`):
- Binario: 80,3% BENIGN vs 19,7% ataque.
- Multiclase: de DoS Hulk (231.073) a **Heartbleed (11 casos)** — ratio
  206.645:1 frente a BENIGN. Infiltration (36) y SQL Injection (21) tampoco
  soportan métricas por clase.

**Calidad de datos:**
- Inf/NaN: 2.867 filas (0,10%), solo en `Flow Bytes/s` y `Flow Packets/s`
  (divisiones entre duración 0).
- Negativos: el −1 en `Init_Win_bytes_forward/backward` (~1,4M y ~1,0M filas)
  es un **código de "no aplica"**, no un error; 115 filas con duración negativa
  sí son error de captura.
- **Duplicados: 330.995 filas (11,7%)** — riesgo de fuga de información
  (la misma fila en entrenamiento y prueba se "acierta" de memoria).
- 8 features constantes; 51 pares de features con |r| > 0,95
  (figura `reports/figures/02_correlaciones_redundantes.png`).

**Estructura temporal:** cada tipo de ataque ocurre en **un único día** y el
lunes es 100% benigno → la validación multiclase debe ser aleatoria
estratificada (un split por días dejaría ataques sin representar), y el lunes
habilita el enfoque no supervisado de la pregunta 3.

### Preguntas de negocio (aprobadas; detalle en `preguntas_de_negocio.md`)

1. **Interpretabilidad** — ¿qué features distinguen ataque de tráfico normal?
   ✅ sobrevive tal cual.
2. **Multiclase con desbalance** — ¿qué tan bien se clasifica el tipo de
   ataque y qué técnicas de desbalance ayudan? ⚠️ sobrevive **con ajustes**:
   los 3 ataques web se agrupan en la familia "Web Attack"; Heartbleed e
   Infiltration quedan fuera del multiclase (se evalúan a nivel binario).
3. **No supervisado** — ¿un modelo entrenado solo con tráfico normal detecta
   ataques no vistos? ✅ sobrevive como complementaria.

### Las 6 decisiones de limpieza aprobadas y su porqué

| # | Decisión | Porqué |
|---|---|---|
| 1 | Eliminar duplicados | Evitar fuga de información entre train y test |
| 2 | Eliminar filas con Inf/NaN | Son 0,10%, concentradas en 2 features de tasa |
| 3 | Eliminar duraciones negativas | Error de captura, físicamente imposible |
| 4 | −1 de `Init_Win_bytes_*` → indicador binario + 0 | Es un código de "no aplica", no un número |
| 5 | Eliminar 8 features constantes y podar redundantes | Cero información; las redundantes ensucian la interpretación |
| 6 | Split aleatorio estratificado | Cada ataque ocurre un solo día |

---

## Fase 2 — Preprocesamiento, split único y líneas base

### Limpieza aplicada (`src/limpieza.py`)

| Paso | Filas eliminadas |
|---|---|
| Duplicados | 330.995 (11,69%) |
| Inf/NaN en features de tasa | 1.563 |
| Duración negativa | 107 |
| **Resultado** | **2.830.743 → 2.498.078 (88,25%)** |

Además: indicadores `Init_Win_bytes_*_no_aplica`, 8 constantes eliminadas,
verificación automática de que no queda ningún Inf/NaN. Guardado en
`data/interim/cicids2017_limpio.parquet`.

### Split único (`src/split.py`)

80/20 estratificado por clase, `RANDOM_STATE = 42`, hecho **una sola vez**:
train 1.998.462 / test 499.616 filas. El test ronda 20% en todas las clases
(incluso Heartbleed: 9/2). **Regla del proyecto: el test no se toca hasta la
evaluación final**; el script se niega a regenerar el split si ya existe.

### Selección de features (`src/features.py`, decidida SOLO con train)

Sobre una muestra de 500.000 flujos del train: 45 pares con |r| > 0,95 forman
13 grupos; de cada grupo se conserva **una** representante elegida por
interpretabilidad (p. ej. `Flow Duration` en vez de `Fwd IAT Total`).
Resultado: **71 → 48 features**. Los grupos son re-derivables con
`calcular_grupos()` y la lista curada se validó contra los datos.

### Líneas base (`notebooks/02_baseline.ipynb`, CV estratificada 5 folds, solo train)

Reglas: escalado dentro del pipeline; pipelines de `imblearn` listos para
insertar remuestreo; **sin accuracy** (el piso "acierta" 83% sin detectar ni
un ataque).

| Modelo | macro-F1 (CV) |
|---|---|
| Binaria — piso (siempre "Normal") | 0,453 |
| Binaria — regresión logística | 0,921 |
| Multiclase — piso (siempre "BENIGN") | 0,082 |
| Multiclase — regresión logística | 0,701 |

Binaria: recall de ataque 0,857 con precisión 0,879 (figura
`reports/figures/04_pr_binaria.png`). Multiclase: las clases grandes salen
casi perfectas (DDoS F1 0,989; DoS Hulk 0,969), pero **las minoritarias casi
no se detectan sin corrección del desbalance** (figuras
`reports/figures/05_matriz_confusion_multiclase.png` y
`reports/figures/06_pr_minoritarias.png`):

| Clase | Recall (base) | AP (base) | Diagnóstico |
|---|---|---|---|
| SSH-Patator | 0,208 | 0,80 | El modelo la *ordena* bien pero el umbral la ahoga: reponderar debería bastar |
| DoS Slowhttptest | 0,796 | 0,85 | Recuperable |
| DoS slowloris | 0,885 | 0,91 | Casi resuelta |
| Bot | 0,015 | 0,21 | **Atascada**: el modelo lineal no la separa |
| Web Attack | 0,003 | 0,20 | **Atascada**: ídem |

Esta brecha es exactamente lo que los experimentos de la Fase 3 deben cerrar,
con el mismo split, CV y features.

**Decisión documentada pendiente de ratificar:** SQL Injection (21 casos)
quedó **dentro** de la familia "Web Attack", no como clase excluida
(`src/etiquetas.py`).

---

## Fase 3 — Experimentos de desbalance (pregunta 2)

### Diseño: matriz 2 × 4 para atribuir cada mejora a su causa

Dos ejes cruzados, en condiciones idénticas a las líneas base (mismo split —
**el test sigue sin tocarse** —, misma CV estratificada de 5 particiones,
mismas 48 features, semilla 42):

- **Eje A (capacidad):** regresión logística vs árboles con boosting
  (`HistGradientBoostingClassifier`).
- **Eje B (desbalance):** sin corrección / pesos de clase / SMOTE /
  submuestreo de BENIGN + SMOTE — siempre DENTRO del `imblearn.Pipeline`
  (solo afecta el tramo de entrenamiento de cada partición).

Elecciones de remuestreo: SMOTE eleva las clases con < 20.000 casos hasta
20.000 (igualarlas a BENIGN fabricaría ~14M de filas sintéticas);
el submuestreo reduce BENIGN a 200.000 antes de SMOTE.

Cómputo de una sola vez (~40 min en 24 núcleos) con `src/experimentos.py`;
resultados condensados a CSVs de KB en `reports/resultados_fase3/` por
`src/resultados.py`. El notebook `03_desbalance.ipynb` solo lee esos CSVs y
corre en segundos en cualquier máquina.

### Resultados: macro-F1 (media ± desviación entre 5 particiones)

| Modelo | Técnica | macro-F1 |
|---|---|---|
| **Árboles (HistGB)** | **Pesos de clase** | **0,970 ± 0,002** |
| Árboles (HistGB) | SMOTE | 0,966 ± 0,003 |
| Árboles (HistGB) | Sin corrección | 0,948 ± 0,008 |
| Árboles (HistGB) | Submuestreo + SMOTE | 0,937 ± 0,046 |
| Regresión logística | SMOTE | 0,832 ± 0,005 |
| Regresión logística | Sin corrección | 0,700 ± 0,014 |
| Regresión logística | Submuestreo + SMOTE | 0,650 ± 0,002 |
| Regresión logística | Pesos de clase | 0,543 ± 0,004 |

(Figura `reports/figures/07_macro_f1_experimentos.png`; detalle por clase en
`reports/figures/08_recall_minoritarias.png` y en los CSVs.)

### Análisis (lo que piden las preguntas de la fase)

**1. Clases que solo necesitaban reponderar o mover el umbral.** SSH-Patator
tenía recall 0,21 pero AP 0,80 con la logística sin corrección: el modelo ya
la ordenaba bien y el umbral la ahogaba. Cualquier corrección la libera
(recall 0,92-0,98); con árboles llega a recall 1,00 con precisión 0,997.
DoS slowloris (AP base 0,91) y DoS Slowhttptest (0,85) son análogas.

**2. Las atascadas (Bot y Web Attack, AP base 0,22 y 0,30) NO eran un
problema de desbalance sino de capacidad del modelo.** Con la logística,
ninguna técnica las desatasca: pesos de clase les sube el recall a 0,99/0,96
pero con precisión **0,02/0,03** (98 de cada 100 alarmas de Bot serían
falsas), y SMOTE apenas mueve el AP (Web Attack 0,30 → 0,58). **Los árboles
sí las recuperan**, incluso sin corrección alguna (Bot AP 0,22 → 0,54; Web
Attack 0,30 → 0,85), y con pesos encima quedan en **Bot AP 0,91 (recall
0,98)** y **Web Attack AP 0,99 (recall 0,99, precisión 0,95)**. No hay techo
del enfoque que declarar en estas clases: el "techo" era la linealidad.
Figura `reports/figures/10_pr_clases_atascadas.png`.

**3. El costo en falsas alarmas de cada técnica.** Reponderar la logística la
vuelve inutilizable: BENIGN cae a recall 0,842 (~264.000 flujos normales
marcados como ataque). La mejor combinación (árboles + pesos) paga un costo
casi nulo: **3.157 falsas alarmas en 1.657.869 flujos benignos (0,19%)**.
El eje del modelo pesó más que el del desbalance: el peor árbol (0,937)
supera a la mejor logística (0,832); reponderar solo ayuda cuando el modelo
puede representar la frontera (árboles 0,948 → 0,970 con pesos).

### Mejor combinación y residuos honestos

**Árboles + pesos de clase** (matriz de confusión out-of-fold en
`reports/figures/09_confusion_mejor_combinacion.png`):
- Recall ≥ 0,98 en 9 de 11 clases; BENIGN 0,998 con precisión 1,000.
- **Residuo 1 — precisión de Bot: 0,61.** 967 flujos benignos se confunden
  con Bot (~4 de cada 10 alarmas de Bot son falsas). Su AP de 0,91 indica que
  el umbral es ajustable (tuning de la fase final, no de esta).
- **Residuo 2 — submuestreo+SMOTE es inestable en árboles** (desviación
  0,046; un fold cayó a 0,846): descartada.
- Los ejemplos SMOTE son sintéticos (interpolaciones): útiles para entrenar,
  pero las métricas se calculan siempre sobre flujos reales de validación.

### Nota transversal: estrategia de cómputo y reproducibilidad

El proyecto separa deliberadamente el **cómputo pesado** (que se paga una sola
vez, en la máquina del autor) de la **presentación y verificación** (que debe
funcionar en cualquier equipo). La razón: no es razonable exigir al jurado o a
colaboradores un hardware equivalente para evaluar el trabajo.

1. Los entrenamientos costosos viven en scripts (`src/experimentos.py`), no en
   notebooks. Cada combinación queda **checkpointeada** en `data/interim/fase3/`:
   si el script se interrumpe o se relanza, no repite lo ya calculado. **No hay
   ninguna necesidad de volver a correr los experimentos**: sus resultados son
   deterministas (semilla 42) y quedaron persistidos.
2. Esos resultados se condensan (`src/resultados.py`) en CSVs de kilobytes en
   `reports/resultados_fase3/`, que **sí se versionan con el repositorio**. El
   notebook `03_desbalance.ipynb` se alimenta exclusivamente de ellos: cualquier
   persona puede re-ejecutarlo en segundos y regenerar todas las tablas y
   figuras sin re-entrenar nada.
3. Los notebooks se entregan **ya ejecutados** (outputs embebidos) y este
   informe contiene las mismas cifras: evaluar el proyecto no requiere correr
   código en absoluto.
4. La reproducción completa desde los CSV crudos queda documentada en el README
   (tiempos por paso, ~8 GB de RAM) como garantía de auditabilidad — es
   opcional, no un requisito de evaluación.

### Decisión propuesta (pendiente de aprobación)

Ratificar **árboles + pesos de clase** como candidato para la única
evaluación final sobre el test, y proceder con la pregunta 1
(interpretabilidad) y la pregunta 3 (no supervisado con el lunes benigno).

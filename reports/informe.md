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

---

## Fase 4 — Interpretabilidad (pregunta 1) y detección no supervisada (pregunta 3)

Todo sobre el conjunto de entrenamiento (el test sigue intacto), mismas 48
features, CV estratificada de 5 particiones, semilla 42. Cómputo pesado
checkpointeado en `src/interpretabilidad.py` y `src/no_supervisado.py`; los
notebooks `04_interpretabilidad.ipynb` y `05_no_supervisado.ipynb` solo leen
los CSVs de `reports/resultados_fase4/`.

### Pregunta 1 — ¿Qué distingue un ataque del tráfico normal?

**La historia legible (regresión logística estandarizada, binaria).** Los
coeficientes más grandes (media ± desv entre 5 particiones, figura
`reports/figures/11_coeficientes_logistica.png`) cuentan una historia de
**ritmo**: las features IAT (silencio entre paquetes: `Fwd IAT Mean` −12,0,
`Fwd IAT Min` +11,5, `Fwd IAT Std` +8,6) describen el tráfico "metrallador"
de las herramientas automatizadas; `Packet Length Variance` (+11,3) delata
tamaños de paquete anormalmente dispares; `Flow Duration` (+5,1) captura las
conexiones eternas de los DoS lentos; y el indicador
`Init_Win_bytes_forward_no_aplica` (−8,7) resultó informativo por sí mismo
(valida la decisión de limpieza de tratar el −1 como código).

**El modelo real (importancia por permutación, HistGB + pesos, binario).**
Top: `Flow Duration` (0,086), **`Destination Port` (0,072)**,
`Bwd Packet Length Min/Mean`, `Fwd Packet Length Max`, `Bwd Header Length`,
`Flow Bytes/s`, `Init_Win_bytes_forward(_no_aplica)`
(figura `reports/figures/12_importancia_permutacion.png`).

**Cruce de rankings:** coinciden en el núcleo (duración, ritmo IAT, tamaño
máximo de ida, el indicador de no-aplica); divergen en el énfasis (la
logística exprime el ritmo; los árboles, los tamaños de respuesta y el
puerto). El ranking entregable con explicación por feature está en el
notebook 04.

**El experimento del puerto (verificación de validez central).**
`Destination Port` es el único identificador entre las 48 features y era el
puesto 2 de la permutación. Reentrenando el campeón multiclase sin él
(mismas particiones):

| | Con puerto | Sin puerto |
|---|---|---|
| macro-F1 | 0,970 ± 0,002 | 0,950 ± 0,004 |
| Recall (peor delta) | — | −0,005 (SSH-Patator); Bot +0,004 |
| Precisión Bot | 0,614 | 0,461 |
| Precisión Web Attack | 0,952 | 0,872 |

**Veredicto sin maquillar:** el modelo **no se derrumba: aprende
comportamiento**. El recall se mantiene en todas las clases; el costo del
puerto está localizado en la **precisión** de las dos clases difíciles (Bot,
Web Attack): sin el puerto, el modelo confunde más benignos con esas clases.
El puerto no sostenía la detección, pero ayudaba a descartar falsas alarmas.
La variante sin puerto (0,950) es la estimación honesta para una red donde
los servicios no usen puertos canónicos
(figura `reports/figures/13_experimento_puerto.png`).

### Pregunta 3 — ¿Detecta ataques un modelo entrenado solo con tráfico normal?

Isolation Forest (principal) y LOF (contraste, submuestra de 50.000)
entrenados con los **394.236 benignos del lunes** del train (escalado ajustado
solo con ellos); evaluados sobre martes-viernes del train (1.604.226 flujos,
340.593 ataques). Umbral por cuantiles del score del lunes (0,5%/1%/2%;
referencia 1%) — equivale al parámetro de contaminación y reconoce la posible
presencia de ataques sin etiquetar en el "benigno" (Engelen 2021; Lanvin 2023).

**Resultado central (umbral 1%, figura
`reports/figures/14_recall_no_supervisado.png`):** el detector parte los
ataques en dos mundos:

| Mundo | Clases (recall IF @1%) | Por qué |
|---|---|---|
| Visibles: flujos estructuralmente raros | **Heartbleed 0,89 · Infiltration 0,48 · DoS slowloris 0,52** · DoS Hulk 0,24 | El flujo individual ya es anómalo (exfiltración gigante, conexión eterna) |
| Invisibles: ataques camuflados | FTP/SSH-Patator, PortScan, Web Attack, Bot: **0,000** | Cada flujo parece una conexión normal; lo anómalo es el *agregado* de miles de flujos, que un detector por-flujo no puede ver |

Recall global de ataques al 1%: **11,8%** — como detector general, no sirve.
Pero **Heartbleed e Infiltration son exactamente las clases que el multiclase
supervisado tuvo que excluir por falta de datos**: el no supervisado
complementa al supervisado justo donde este no llega, sin usar una sola
etiqueta. El LOF confirma la complementariedad por contraste (ve SSH-Patator
0,91 y algo de PortScan; pierde Heartbleed y los DoS lentos).

**Falsas alarmas por día (figura
`reports/figures/15_falsas_alarmas_por_dia.png`):** la mayoría de los días
0,7-1,8% (consistente con el umbral del 1%), pero el viernes en la tarde
(archivo del DDoS) el IF dispara **9,6%** de falsas alarmas sobre benignos:
la deriva temporal del tráfico normal es un costo real del enfoque. Scores en
`reports/figures/16_scores_no_supervisado.png`.

**Limitaciones documentadas:** posible contaminación del "benigno" del lunes
(errores de etiquetado en la literatura; mitigado con umbral por cuantiles,
no descartable); LOF con submuestra por costo; resultados sobre
entrenamiento (la evaluación en test será única, en la fase final).

### Documentos de entrega

Se creó el **esqueleto** de `reports/informe_final.md` (documento de ENTREGA,
limpio): solo títulos de sección con marcador "pendiente"; se redactará en la
fase final, cuando existan la evaluación única sobre el test. Este documento
(`informe.md`) sigue siendo el de TRABAJO, acumulativo.

### Pendiente para la fase final (única evaluación sobre el test)

1. Entrenar el campeón (árboles + pesos, con y sin puerto) sobre TODO el
   entrenamiento y evaluarlo UNA vez sobre `test.parquet`.
2. Umbral de Bot: explorar el intercambio precisión/recall (AP 0,91 lo
   permite) ANTES de tocar el test.
3. Evaluar el Isolation Forest del lunes sobre el test (martes-viernes).
4. Redactar `informe_final.md` completo.

---

## Fase final — Evaluación única sobre el test e informe de entrega

### Verificaciones previas (antes de tocar el test)

- Ningún módulo lee `test.parquet` salvo `src/evaluacion_final.py` (verificado
  con búsqueda en todo el código: solo `config.py` lo define y `split.py` lo
  crea con guardia anti-regeneración).
- El split no se regeneró: `train/test.parquet` conservan su fecha de creación
  (2026-07-07).
- `Destination Port` es el ÚNICO identificador entre las 48 features (se buscó
  también `Protocol`, puertos de origen, IPs, timestamps: no sobrevivió ninguno
  a la selección; "Idle Std" aparece en la búsqueda por subcadena pero es una
  feature de comportamiento).

### Paso 1 — Umbral de Bot (solo con train)

Con las probabilidades out-of-fold del train (Fase 3/4): **alarma de Bot solo
si P(Bot) ≥ 0,999**; si no, el flujo se reasigna a la segunda clase más
probable. Intercambio en train OOF: con puerto, precisión 0,61→0,93 con recall
0,98→0,68; sin puerto, 0,46→0,87 con recall 0,61. Nota técnica: las
probabilidades OOF están guardadas en float16, lo que hace el umbral grueso
(cercano al extremo de la escala) — esto resultó relevante después.

### Pasos 2-4 — Resultados del test (única pasada, `src/evaluacion_final.py`)

| Test | macro-F1 | macro-F1 solo ataques |
|---|---|---|
| **Modelo final (con puerto + umbral Bot)** | **0,975** | **0,972** |
| Con puerto, argmax | 0,967 | 0,964 |
| Sin identificadores, argmax | 0,942 | 0,937 |
| Sin identificadores, umbral Bot | 0,888 | 0,877 |

- **CV ≈ test, dicho explícitamente:** 0,970 ± 0,002 (CV) vs 0,967 (test) con
  puerto; 0,950 ± 0,004 vs 0,942 sin identificadores. **No hubo sobreajuste.**
- **El umbral de Bot transfirió en la variante con puerto** (precisión 0,947 /
  recall 0,728 en test, diseñado a 0,93/0,68) y **NO transfirió sin puerto**:
  ese modelo nunca produjo P(Bot) ≥ 0,999 en test → 0 alarmas de Bot (por eso
  0,888). Siguiendo la regla de la fase, NO se reajustó nada tras ver el test;
  queda como lección: umbral fijado en el extremo de la escala + cambio de
  variante = frágil. La cifra honesta sin identificadores es la de argmax
  (0,942).
- Falsas alarmas del modelo final sobre BENIGN en test: **0,12%** (489 de
  414.468). Matriz de confusión:
  `reports/figures/17_confusion_test_final.png`.
- **Ultra-raras (ilustrativo, n mínima):** el binario (recall ataque 1,000,
  precisión 0,994 en test) marcó Heartbleed 2 de 2 e Infiltration 3 de 7.
- **Isolation Forest sobre test:** replica el train — 11,8% global @1%;
  slowloris 0,52, Hulk 0,24, Heartbleed 1 de 2, Infiltration 4 de 7 (n mínima);
  camuflados en ~0; falsas alarmas 9,6% el viernes-tarde, ~1% el resto
  (el lunes del test, nunca visto, dio 0,98%: umbral bien calibrado).

Resultados en `reports/resultados_final/` y `notebooks/06_evaluacion_final.ipynb`.

### Paso 5 — Informe de entrega

`reports/informe_final.md` redactado completo desde este documento: limpio,
en lenguaje llano, con ambas cifras al frente (0,975/0,970 con puerto;
0,942-0,950 como estimación conservadora sin el artefacto, NO como desempeño
garantizado en red real), macro-F1 solo-ataques junto al global, coincidencia
temática (no feature a feature) de los rankings, el indicador `_no_aplica`
como decisión de limpieza vuelta señal, SQL Injection dentro de la familia
Web Attack, el punto ciego del no supervisado como límite del enfoque, y la
sección de limitaciones completa.

**Proyecto cerrado del lado de cómputo. Regla vigente: los resultados del test
no se usan para reajustar ningún modelo.**

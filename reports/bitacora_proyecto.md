# Bitácora del proyecto — Detección de tráfico de red malicioso (CIC-IDS2017)

> **Qué es este documento.** La evidencia del proceso: qué se hizo en cada
> fase, qué se decidió, por qué, y qué se encontró por el camino (incluidos
> los errores y cómo se corrigieron). Se queda en el repositorio de trabajo y
> **no viaja a la entrega**. Los documentos de entrega son el reporte técnico
> (`reporte_tecnico_experimentos.pdf`) y el informe resumido
> (`informe_final.md`).
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

### Las tres preguntas de negocio (evaluadas contra el EDA, aprobadas y ejecutadas)

Las tres candidatas se contrastaron con lo que el EDA mostró que los datos
realmente soportan. Ninguna quedó invalidada; la 2 exigió reformulación. Se
adoptaron las preguntas 1 y 2 como núcleo de la tesis y la 3 como capítulo
complementario. Su versión final, con el método tal como se ejecutó:

**Pregunta 1 — Interpretabilidad** (✅ sobrevivió tal cual): *¿qué
características del tráfico distinguen un ataque del tráfico normal y cuáles
son las más informativas?* La soportan 77 features numéricas homogéneas en
2,8M de flujos, con diferencias visibles entre normal y ataque pero con
solapamiento (ninguna feature separa sola: el caso donde un análisis
multivariado aporta); el desbalance binario (80/20) es moderado. Condición
previa detectada por el propio EDA: podar las 8 features constantes y los
51 pares con |r| > 0,95, porque dos columnas idénticas se "reparten" la
importancia y dañan la interpretación. Método ejecutado (Fase 4): regresión
logística estandarizada (signo y magnitud de coeficientes) contrastada con la
importancia por permutación del modelo de árboles campeón, más la
verificación del puerto de destino como control de artefactos.

**Pregunta 2 — Multiclase con desbalance** (⚠️ sobrevivió con ajustes): *¿qué
tan bien se clasifica el TIPO de ataque y qué técnicas de desbalance mejoran
la detección de los tipos poco frecuentes?* 11 de las 14 clases de ataque
tienen datos suficientes para CV estratificada; tres no soportan métricas por
clase (Infiltration 36, SQL Injection 21, Heartbleed 11 — con 5 particiones,
Heartbleed aporta ~2 casos por fold y cualquier cifra sería ruido; ningún
sobremuestreo fabrica información que no está). Ajustes adoptados: los 3
ataques web se agrupan en la familia **"Web Attack"** (SQL Injection incluida
en la familia — ratificado); **Heartbleed e Infiltration quedan fuera del
multiclase** y se evalúan aparte a nivel binario, reportadas siempre con su n
y sin promediarlas. La deduplicación redujo SSH-Patator 45% y PortScan 43%,
pero ambas conservan miles de casos y siguieron viables. Método ejecutado
(Fase 3): matriz 2×4 (logística/HistGradientBoosting × sin corrección/pesos/
SMOTE/submuestreo+SMOTE) con CV estratificada, evaluada con macro-F1, recall
y precisión por clase, matrices de confusión y curvas PR — nunca accuracy
(decir "todo es normal" ya acierta 80%).

**Pregunta 3 — No supervisado** (✅ sobrevivió como complementaria): *¿un
modelo entrenado únicamente con tráfico normal puede señalar como anómalos
ataques que nunca vio etiquetados?* La habilita un hallazgo del EDA: el lunes
es 100% benigno (529.918 flujos) y los demás días aportan los 14 ataques como
evaluación. Advertencias asumidas desde el diseño: los errores de etiquetado
documentados en la literatura pueden contaminar el "benigno" del lunes (se
manejó fijando el umbral por cuantiles de los scores del propio lunes —
0,5%/1%/2%, el equivalente explícito del parámetro de contaminación), y el
tráfico normal varía entre días, así que las falsas alarmas se reportan POR
DÍA. Método ejecutado (Fase 4): Isolation Forest como detector principal y
Local Outlier Factor como contraste, solo scikit-learn.

### Las 6 decisiones de limpieza (aprobadas y aplicadas en la Fase 2) y su porqué

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

Esta brecha es exactamente la que los experimentos de la Fase 3 debían
cerrar — y cerraron (ver Fase 3) — con el mismo split, CV y features.

**Decisión documentada y ratificada:** SQL Injection (21 casos) quedó
**dentro** de la familia "Web Attack", no como clase excluida
(`src/etiquetas.py`). La familia agrupa los tres ataques a la aplicación web;
SQL Injection no se evalúa como subtipo propio por falta de muestras.

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
problema de desbalance sino de capacidad del modelo.** (Los AP de esta
sección son medias entre las 5 particiones de la Fase 3; el notebook 02
reporta 0,21 y 0,20 sobre las predicciones agrupadas de la validación cruzada
— misma señal, estimador distinto.) Con la logística,
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

Decisión de arquitectura tomada en esta fase: separar el **cómputo pesado**
(scripts checkpointeados, se paga una sola vez en la máquina del autor) de la
**presentación** (notebooks e informes que leen resultados condensados en CSVs
de kilobytes versionados con el repo). El porqué: evaluar el proyecto no debe
exigir hardware ni re-entrenamientos — los notebooks se entregan ejecutados y
cualquiera puede regenerar tablas y figuras en segundos. El detalle operativo
(niveles de consumo, tiempos por paso, requisitos) vive en el
[README](../README.md).

### Decisión de la fase (aprobada)

**Árboles + pesos de clase** quedó ratificado como el candidato para la única
evaluación final sobre el test, donde efectivamente confirmó su desempeño
(macro-F1 0,975 con la regla de operación completa; ver Fase final). Con esa
decisión tomada, la Fase 4 abordó la pregunta 1 (interpretabilidad) y la
pregunta 3 (no supervisado con el lunes benigno).

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
entrenamiento (la evaluación sobre el test fue única, en la fase final).

### Documentos de entrega

En esta fase se creó el **esqueleto** de `reports/informe_final.md` (el
informe resumido de entrega), que se redactó completo al cierre de la fase
final, una vez existió la evaluación única sobre el test.

### Plan para la fase final (ejecutado tal cual en la fase siguiente)

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

### Trabajo futuro (desarrollado en el informe resumido, §6)

Features agregadas por ventana temporal (para los ataques "camuflados" que el
detector por-flujo no puede ver), calibración de probabilidades antes de fijar
umbrales de operación (la lección del umbral de Bot), y validación sobre la
versión corregida del dataset (LYCOS-IDS2017) y sobre tráfico real.

**Proyecto cerrado del lado de cómputo. Regla vigente: los resultados del test
no se usan para reajustar ningún modelo.**


---

## Fase A — Artefactos del prototipo (septiembre de 2026)

El proyecto pivotó de tesis analítica a **prototipo entregable**: un tablero
web donde un analista carga un archivo de flujos y obtiene, por flujo, si es
ataque, de qué tipo, con qué confianza y por qué. La fuente de verdad del
tablero es `docs/especificacion_prototipo.md` (22 requerimientos, 6 pantallas,
cifras oficiales en su §10). El análisis quedó cerrado: nada de esta fase
recalculó cifras ni tocó el conjunto de prueba.

### Modelos serializados (`models/`, `src/modelo_final.py`)

Se re-entrenaron con todo el entrenamiento y se guardaron con `joblib`
(compresión 3): `modelo_multiclase.joblib` (HistGB + pesos, 11 clases,
0,7 MB), `modelo_binario.joblib` (0,2 MB) y `detector_anomalias.joblib`
(Isolation Forest + `StandardScaler` ajustado solo con el lunes benigno +
umbrales por cuantiles 0,5 / 1 / 2 %; 0,4 MB), más `metadatos.json` (lista
ordenada de las 48 características, nombres de clases, umbral de Bot 0,999 y
su regla, versión de scikit-learn, semilla). Total 1,3 MB. **Determinismo
verificado:** los umbrales del detector re-entrenado coinciden decimal a
decimal con los del checkpoint de la evaluación final.

### Archivos de demostración (`data/demo/`, `src/preparar_demo.py`)

Dos muestras estratificadas del **conjunto de prueba** (el modelo nunca las
vio): `flujos_demo.csv` (499 flujos, 39,9 % de ataque, los 14 tipos) para
mostrar todo lo que se detecta, y `flujos_demo_realista.csv` (500 flujos,
5,0 % de ataque) para mostrar cuánto trabajo ahorra. Ambas en el esquema
crudo completo de CICFlowMeter (78 columnas con sus espacios, la columna
repetida, el −1 restaurado), sin la columna de etiqueta; las etiquetas van
aparte en archivos que el tablero nunca lee. `.gitignore` las exceptúa de la
regla `*.csv`.

### Decisiones técnicas de la fase

- **Explicación por alerta (R3): SHAP `TreeExplainer`** soporta el HistGB
  multiclase: 0,12 s de inicialización, 2 ms por flujo, y en el 100 % de los
  flujos probados la clase más empujada coincide con la predicha. Costo:
  ~100 MB de memoria por numba/llvmlite (cabe en 1 GB). Plan B documentado:
  desviación del flujo frente al rango benigno (sin dependencias).
- **R9 medido en local:** 10.000 / 50.000 / 100.000 flujos en 0,2 / 0,8 /
  1,6 s por el camino completo; pico 392 MB. En una repetición posterior:
  0,7 s y 390 MB. La medición definitiva se repite sobre el tablero
  desplegado (así lo dice la prueba prevista de R9).
- **Entornos separados:** `requirements.txt` liviano para la app (streamlit,
  scikit-learn 1.9.0, pandas, numpy, joblib, shap, pytest) y
  `requirements-analisis.txt` con el `pip freeze` completo del análisis.
  Regla no negociable: **scikit-learn idéntico en ambos**, porque de esa
  versión depende que los `.joblib` carguen; el tablero verifica la versión al
  arrancar. Despliegue con Python 3.13.
- **Licencias:** todas las dependencias son BSD / MIT / Apache 2.0 / PSF.
  Cita obligatoria del dataset (texto exigido por su proveedor): *Iman
  Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating
  a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
  4th International Conference on Information Systems Security and Privacy
  (ICISSP), Portugal, January 2018.*
- **Entorno mínimo:** usuario final, navegador de escritorio y la URL; para
  reproducir el análisis, Python 3.13, versiones exactas y ~8 GB de memoria
  (el tablero solo necesita ~1 GB).

---

## Fase B — Construcción del tablero (Streamlit)

Seis pantallas en un enrutador de una sola página (`streamlit_app.py` +
`app/{nucleo,validacion,pantallas}.py`): Panel de resumen, Clasificación,
Detección de anomalías, Interpretabilidad, Alertas y Reportes. Los modelos se
cargan una vez por servidor (`st.cache_resource`) y nada del archivo del
usuario se escribe a disco.

### Decisiones de diseño

- **El KPI de negocio primero (R5):** el panel de resumen encabeza con la
  reducción de la carga de revisión (con la demo realista: 500 flujos → 23
  alertas → 95,4 % menos revisión) y, obligatoriamente al lado, la frase que
  declara el intercambio: sin herramienta se revisa todo y no se escapa nada
  a costa de un trabajo inviable; con herramienta se revisa una fracción y
  se acepta que algo pueda pasar.
- **Una alerta es un flujo cuya clase final ≠ Normal** según el modelo oficial
  (multiclase + regla de Bot). El binario y la marca de anomalía son columnas
  complementarias, no definen la alerta.
- **El umbral del detector es un presupuesto de falsas alarmas** (0,5 / 1 /
  2 %, calibrado con el lunes benigno). El deslizador vive en la pantalla de
  anomalías y su valor rige también la marca de anomalía en Alertas y en el
  Panel de resumen. Con la demo rica: 8 / 22 / 36 anómalos.
- **Interpretabilidad en dos niveles y dos modelos distintos:** la importancia
  global se midió sobre el modelo **binario** (ataque sí/no) y la explicación
  por alerta (SHAP) sobre el **multiclase**; la pantalla lo dice
  explícitamente después de detectar que la primera versión los presentaba
  como si fueran el mismo modelo. La tabla global se muestra ordenada y con
  nombres en lenguaje llano (glosario de las 48 características).
- **Las filas con valores inválidos se excluyen y se nombran**, no se imputan.
- **Tres modelos, no uno:** las pantallas de Clasificación y Alertas explican
  que el multiclase aprendió 10 tipos y no 14 (Heartbleed e Infiltration son
  demasiado escasos); si aparecen, su tipo asignado será incorrecto por
  construcción, pero el binario y el detector de anomalías pueden atraparlos.
- **Lo que deliberadamente no tiene** (declarado en pantalla): exportación en
  PDF, historial entre sesiones, columna de severidad, tiempo real.

### Errores encontrados probando en un navegador real (no en el código)

1. Al elegir una demo con un archivo ya subido, el archivo subido volvía a
   imponerse al cambiar de pantalla. Causa: se limpiaba el estado del cargador
   en vez de marcar el archivo como atendido. Corregido y verificado con una
   subida real.
2. El deslizador del umbral se dibujaba en 0,5 % mientras el sistema usaba
   1 %: Streamlit no refleja un `session_state` preinicializado en la posición
   del control. Corregido dando el valor por defecto al propio widget.
3. `KeyError: 'importancia'` en una segunda instancia del servidor que llevaba
   dos horas corriendo: **`st.cache_resource` no se invalida cuando cambia el
   código**, así que servía un diccionario de recursos anterior a pantallas
   nuevas. Solución de fondo: el caché se versiona (`VERSION_RECURSOS`, que se
   pasa como argumento a la función cacheada) y el arranque verifica las
   claves requeridas y muestra un mensaje accionable en vez del error. Regla
   operativa: al tocar `app/*.py` o `models/` hay que reiniciar el servidor,
   no basta con recargar la página.
4. `use_container_width` estaba obsoleto (retirado tras 2025-12-31);
   reemplazado por `width="stretch"` en los 11 usos.

### Verificaciones de usabilidad

Recorrido sin archivo cargado en las seis pantallas sin excepciones y con
estado vacío explicado; archivo inválido bloqueado con mensaje en llano
("Faltan 43 de las 46 características…"); todo resultado clave a ≤ 3 clics;
auditoría de 14 términos técnicos, todos con glosa; arranque en caliente
1,3 s, en frío ~35 s.

---

## Fase C — Verificación del reporte técnico y cierre del tablero

### El reporte técnico del Módulo 2 (`reporte_tecnico_experimentos.pdf`)

Escrito en LaTeX (fuente en `reporte_tecnico_experimentos.tex`, compilado con
Tectonic porque la máquina no tiene LaTeX; alternativa: Overleaf). Antes de
entregarlo se contrastó cada afirmación con el código y los datos:

- **Local Outlier Factor, confirmado con cifras** (recall al 1 %, evaluación
  sobre la semana): ve la fuerza bruta contra SSH que el Isolation Forest no
  ve (0,906 frente a 0,000) pero **no** la de FTP (ambos 0,000); pierde
  Heartbleed (0,000 frente a 0,889) y slowloris (0,000 frente a 0,520); su
  recall global es un tercio del elegido (0,035 frente a 0,118). Por eso la
  frase dice "contra SSH" y no "la fuerza bruta".
- **Tres cifras corregidas:** "27 pruebas" eran **25**; "500 flujos de demo"
  eran **499 y 500**; "0,8 s / 392 MB" se reformuló como "menos de un segundo
  (0,7–0,8 s) y pico cercano a 390 MB", porque una medición de tiempo varía
  entre ejecuciones y la formulación con rango resiste que la repitan.
- La versión definitiva del PDF incorpora las ediciones hechas en Overleaf
  (usuario que conoce redes pero no programa; aclaración de que el 83 % de
  benigno es tras deduplicar y el 80,3 % en crudo; "por primera y única vez";
  licencias sin código de requerimiento; sección de calibración de
  hiperparámetros). El `.tex` del repositorio fue anterior a esas
  ediciones hasta el 20 de septiembre, cuando se reemplazó por la
  exportación de Overleaf; desde entonces `.tex` y PDF del Módulo 2 quedan
  congelados (ver Fase D).

### Los scripts de prueba se perdieron y se reconstruyeron desde la tabla

Los 25 casos originales vivían en una carpeta temporal fuera del repositorio
—justo el riesgo declarado en el reporte— y una limpieza automática los borró
el 14 de septiembre. Se reescribieron en `tests/`, esta vez **mapeados uno a
uno contra la columna "Prueba prevista" de la tabla de requerimientos**
(R1–R22): 19 automatizadas y 6 manuales documentadas como omitidas con su
razón (R10, R16, R19, R20, R21-humana, R22), 25 en total. Un solo comando:
`python -m pytest -v`. Hallazgo al escribirlas: `preparar_demo.py` también
lee el conjunto de prueba —legítimamente, para muestrear la demo (§6 de la
especificación)—; la aserción anti-fuga de R8 quedó formulada como "ningún
módulo salvo `evaluacion_final.py` calcula métricas con el test".

### R11 expuesto en el tablero

La pantalla de anomalías muestra la tasa de falsas alarmas del detector por
día/tramo (8 tramos, del CSV de la evaluación final), siguiendo el umbral
elegido, con la explicación de la deriva: el detector se calibró con el lunes;
cuando el tráfico normal de otro día se comporta distinto, las falsas alarmas
suben (un tramo del viernes llegó a 9,6 % frente al ~1 % esperado), y esa
tabla medida periódicamente es lo que permitiría decidir cuándo re-entrenar.

### Orden documental

`informe.md` pasó a llamarse `bitacora_proyecto.md` (este documento; no viaja
a la entrega). El reporte del Módulo 2 pasó a `reporte_tecnico_experimentos`
y se retiraron la versión previa y los duplicados. `notas_equipo.md` se
retiró: su contenido factual vive ahora en las Fases A, B y C de esta
bitácora; el material presentable que listaba está en la sección siguiente.

### Material para la presentación (reunido de las notas del equipo)

- La reducción de la carga de revisión (95,4 % con la demo realista) con su
  frase de intercambio: la diapositiva de propuesta de valor.
- La perilla del detector como "presupuesto de falsas alarmas".
- La explicación por alerta con SHAP: responde a "¿y por qué le creo al modelo?".
- La prueba del puerto (0,970 → 0,950; 0,967 → 0,942 en test): responde a
  "¿no estará haciendo trampa?".
- La comparación de los dos detectores (ven cosas casi opuestas).
- 50.000 flujos en menos de un segundo frente a 30 prometidos.
- Los errores encontrados y corregidos: muestran que se probó de verdad.
- El determinismo bit a bit de los modelos empaquetados y la honestidad de la
  demo (flujos nunca vistos, etiquetas en un archivo que el tablero no lee).


---

## Fase D — Reporte técnico final: la retroalimentación incorporada (20 de septiembre de 2026)

El reporte del Módulo 2 obtuvo **97/100**. Su fuente `reporte_tecnico_experimentos.tex`
(ya con las ediciones de Overleaf) y su PDF quedan **congelados** como registro
de lo calificado: no se tocan (verificado por suma MD5 antes y después de esta
fase). El anexo técnico (ii) de la entrega final evoluciona en una copia,
`reporte_tecnico_final.tex` → `reporte_tecnico_final.pdf` (20 páginas frente a
11), que incorpora la retroalimentación de esa entrega y de la anterior. En
esta fase no se modificó ningún archivo de `src/`, `app/` ni `tests/`, ni
resultado, cifra o checkpoint alguno.

### Qué cambió en el documento

1. **Portada.** Ya no es "Módulo 2": título "Reporte técnico de experimentos",
   subtítulo "Entrega final — Anexo técnico (ii)". Autores sin cambio; la fecha
   la pone la compilación (no hay `\date`), como en el original.
2. **Umbrales por cuantiles explicados** (retroalimentación previa: "no es
   claro cómo se logra establecer los umbrales por cuantiles del lunes"). Nuevo
   párrafo en §5.1 con los cuatro pasos (entrenar solo con el lunes benigno →
   puntuar ese mismo tráfico → fijar el corte en un percentil → marcar lo que
   caiga por debajo), la lectura como *presupuesto explícito de falsas alarmas*,
   por qué el valor numérico del corte (−0,614 al 1 %) no se reporta como
   parámetro, y su relación con la contaminación del lunes y con la deriva
   (R11). Referenciado desde el Cuadro 3 y desde el párrafo de R4 en §7.
3. **Apéndice A — evidencia de colinealidad** (retroalimentación: "anexar una
   lista o mapa de correlaciones"). Cuadro A.1 con los 13 bloques tomados
   *textualmente* de `GRUPOS_CORRELACIONADOS` (`src/features.py`) y **figura
   nueva** `reports/figures/18_correlaciones_train_095.png`: mapa de |r| de las
   36 variables implicadas, ordenadas bloque a bloque, calculado **solo sobre el
   conjunto de entrenamiento** (muestra de 500.000 flujos, semilla 42) y **al
   umbral con el que se decidió (0,95)**, no al 0,999 de la figura 02 del EDA
   (que además usaba el dataset completo). Verificado por código: 45 pares, 13
   componentes conexas, coincidencia exacta con la lista del módulo. Referenciado
   desde el Cuadro 3 (poda 71 → 48) y desde §5.1.
4. **Apéndice B — configuración de parámetros** (retroalimentación: "reporten la
   configuración de los parámetros, no simplemente digan que usaron valores
   estándar"). Nada escrito de memoria: `get_params()` y atributos ajustados de
   los tres modelos de `models/`; los estimadores del protocolo instanciados con
   la misma función que los construyó (`construir_pipeline` de
   `src/experimentos.py`) y las constantes leídas de `src/`. Ocho cuadros
   (B.1–B.8; en la primera versión eran once, ver la revisión de abajo): todos
   los parámetros de cada objeto con la marca explícito / por defecto, más los
   del protocolo (partición, CV, SMOTE, submuestreo, regresión logística, LOF,
   importancia por permutación, umbral de Bot, cuantiles, versiones). El párrafo
   "Calibración de hiperparámetros" de §5.1 ya no habla de "valores estándar":
   remite al apéndice.

### El hallazgo: 200 iteraciones era el techo, no las usadas

`HistGradientBoosting` trae `early_stopping='auto'`, que se activa con más de
10.000 observaciones (siempre, aquí): reserva el 10 % del tramo de entrenamiento
como validación interna, ajusta los árboles con el 90 % restante y se detiene
cuando la pérdida no mejora durante 10 iteraciones. Leído de los modelos
serializados (`n_iter_`): el **multiclase usó 43 iteraciones** (473 árboles = 43
× 11 clases; mejor pérdida en la 33) y el **binario 110** (mejor en la 100). El
documento anterior decía "usa 200 iteraciones"; se corrigió en §5.1 y se
documenta en B.1. Los modelos de cada partición de la CV no se conservaron
(solo sus métricas), así que su cuenta exacta no se reporta.

Otras discrepancias entre documento y código encontradas al leerlo:
- `contamination='auto'` del Isolation Forest queda por defecto porque **no se
  usa**: el corte lo fija el percentil de los scores del lunes; y
  `max_samples='auto'` son 256 flujos por árbol.
- La regresión logística muestra `penalty='deprecated'` (scikit-learn 1.8 lo
  retiró); la regularización efectiva es L2 (`l1_ratio=0.0`) con `C=1.0`, lbfgs.
- Únicos parámetros fijados a mano en todo el prototipo: `class_weight`,
  `max_iter`, `random_state` (clasificadores); `n_estimators`, `random_state`,
  `n_jobs` (bosque); `max_iter=1000`, `random_state` (logística);
  `sampling_strategy` y `random_state` (SMOTE y submuestreo); `novelty`, `n_jobs`
  (LOF). Todo lo demás, por defecto.

### Cómo se generó (reproducible)

`reports/apendices/generar_apendices.py` (entorno de análisis: necesita
imblearn y `data/processed/train.parquet`) re-deriva los bloques, dibuja la
figura 18 y escribe los fragmentos LaTeX (`tabla_bloques.tex`,
`tablas_parametros_modelos.tex`, `tablas_parametros_protocolo.tex`) y los CSV de
evidencia (`bloques_correlacion_train.csv`, `parametros_modelos.csv` con 264
filas, `atributos_ajustados.csv`). Los fragmentos se pegan en el `.tex` (no se
usa `\input`, para que un solo archivo compile en Overleaf). Compilación con
Tectonic: sin errores, referencias resueltas, todas las figuras cargan; las
cifras oficiales del Módulo 2 aparecen íntegras en el PDF final (comparación
automática de todos los números entre ambos PDF). El script vive en
`reports/apendices/` y no en `src/` porque en esta fase `src/` estaba
reservado para la reescritura de comentarios; puede moverse después. Se añadió
`!reports/apendices/*.csv` al `.gitignore` y `reporte_tecnico_final.tex` al
`export-ignore` (mismo criterio que la fuente del Módulo 2: viaja el PDF).

### Revisión del 21 de septiembre: cuatro ajustes tras la lectura del PDF

1. **Cuadro 3, fila del escalado, partida en dos.** Agrupaba regresión
   logística e Isolation Forest bajo "`StandardScaler` dentro del pipeline de
   validación"; para el detector no hay validación cruzada: el escalador se
   ajusta únicamente con los 394.236 flujos benignos del lunes. Cada fila lleva
   ahora su tratamiento.
2. **§5.1 ya no dice "para toda decisión".** La CV de 5 particiones se usó para
   comparar alternativas, elegir modelo y fijar el punto de operación; la
   importancia por permutación se midió con una sola partición (modelo ajustado
   con el 80 % de la primera, medido sobre 300.000 flujos de su validación), por
   costo computacional. El texto lo declara y remite al cuadro del protocolo.
3. **Criterio de "explícito" corregido en el método, no en el caso.** El
   generador decidía "explícito" comparando el valor contra el default, y eso
   fallaba cuando el código fija un valor igual al default (el Cuadro del LOF
   marcaba `n_neighbors=20` como "por defecto" aunque `src/no_supervisado.py`
   lo escribe). Ahora "explícito" = **escrito en la llamada del código**: el
   generador lee las llamadas de `src/` con `ast` (registro en
   `reports/apendices/llamadas_en_codigo.csv`) y marca "explícito (igual al
   defecto)" cuando ambas cosas ocurren. Cambiaron de clasificación **9 filas /
   4 parámetros** (`reports/apendices/cambios_de_criterio.csv`):
   `n_neighbors=20` del LOF; `n_splits=5` de `StratifiedKFold`; `n_repeats=5`
   de `permutation_importance`; y `class_weight=None` en las 6 combinaciones de
   la matriz de la Fase 3 sin pesos de clase (regresión logística y HistGB ×
   sin corrección / SMOTE / submuestreo + SMOTE), porque el código lo escribe
   como `class_weight=peso` y `peso` vale `None` en esas columnas. Hallazgo
   lateral del `ast`: la `LogisticRegression` de `interpretabilidad.py`
   (coeficientes) no escribe `class_weight`; la de `experimentos.py` sí.
4. **Duplicación eliminada sin perder información.** Los dos cuadros de
   `HistGradientBoostingClassifier` (idénticos en sus 21 parámetros) son ahora
   uno, con los atributos ajustados de multiclase y binario en columnas; los
   dos cuadros de `StandardScaler` (enteramente por defecto) se reemplazaron
   por una frase que conserva los 394.236 flujos del lunes. Quedan 8 cuadros
   (B.1 iteraciones, B.2 HistGB, B.3 Isolation Forest, B.4 regresión
   logística, B.5 SMOTE, B.6 submuestreo, B.7 LOF, B.8 protocolo); el CSV de
   264 filas sigue completo como evidencia. Recompilado con Tectonic: **19
   páginas**, referencias resueltas, cifras oficiales íntegras, Módulo 2
   intacto (MD5).

### Pendiente en este documento

- **§8 (estado de implementación y plan) NO se tocó**: se reescribirá al final,
  cuando estén terminados el despliegue, el manual y la prueba de usabilidad,
  para que refleje el estado real. Con ella habrá que actualizar el punto (vi)
  del resumen y la conclusión 5, que remiten al plan.
- Decidir si el `\date` se fija a la fecha de entrega.


---

## Fase E — Revisión de estilo y auditoría general antes del repositorio limpio (22 de septiembre de 2026)

### Textos en el estilo del equipo

Bryan reescribió los textos de tres pantallas del tablero y, siguiendo ese
estilo (sin rayas, sin la estructura "no es X, es Y", sin mayúsculas para
enfatizar), se reescribieron las otras tres pantallas, el markdown y los
comentarios de los seis notebooks, y los comentarios y docstrings de `src/` y
`tests/`. En los notebooks solo cambió texto: las salidas, el código y los
números de ejecución quedaron idénticos (verificado contra el commit). La
prueba de R21 dejó de exigir la frase literal "Qué muestra" y ahora revisa la
estructura (título + descripción, guía "Cómo leer", explicación de cada término
técnico en la misma pantalla donde se usa); se comprobó que detecta cinco
defectos introducidos a propósito.

### Auditoría general

Se verificó todo pensando en que el proyecto se copie a una carpeta nueva:

- **Cifras.** Las 17 cifras oficiales de la especificación se recalcularon desde
  los CSV versionados y coinciden. Las cifras secundarias de notebooks, informe
  final y reporte técnico también se cruzaron contra los datos.
- **Requirements.** Coinciden exactamente con los entornos instalados, cubren
  todos los imports y scikit-learn es el mismo en ambos (1.9.0). Se resolvieron
  para Windows, Linux y Mac con Python 3.13.
- **Carpeta nueva.** Se copiaron solo los archivos del repositorio, se creó el
  entorno desde cero con `requirements.txt` y se siguieron las instrucciones del
  README: 17 pruebas pasan y 8 se omiten (las 6 manuales y las 2 que necesitan
  los datos), el tablero corre sin errores en sus seis pantallas, y los
  notebooks 03 a 06 regeneran sus 11 figuras idénticas píxel a píxel y los
  mismos 1.908 números.

Errores encontrados y corregidos:

1. `requirements-analisis.txt` no se podía instalar en Mac ni Linux porque
   fijaba `pywinpty`, que solo existe en Windows; ahora lleva un marcador de
   plataforma.
2. El README tenía rutas absolutas del equipo de desarrollo y solo explicaba
   Windows; ahora es genérico, cubre Mac y Linux, y agrega dos casos nuevos:
   el Mac con procesador Intel (no puede instalar el entorno del tablero porque
   `numba`, dependencia de SHAP, ya no publica versiones para esa plataforma) y
   el error de rutas de más de 260 caracteres en Windows (encontrado en la
   simulación). También decía "17 figuras" (son 18) y mandaba al reporte del
   Módulo 2 como anexo técnico.
3. Cifras mal escritas: "26 falsas alarmas por cada 100" (son ~16, notebook 03);
   "~9.400 alarmas falsas" el viernes (son ~7.300, notebook 05); "~1,4M de
   negativos" (son ~2,4M, notebook 01); "~40 % de las filas con −1" (es el
   51 %, informe final y reporte técnico); "51 pares con |r| > 0,95" en la
   tabla de limpieza (la decisión se tomó con 45 pares en el entrenamiento);
   "AP ≈ 0,2" para Bot y Web Attack (son 0,22 y 0,30).
4. Afirmaciones inexactas: que slowloris estaba entre las clases que el
   supervisado no pudo aprender (solo Heartbleed e Infiltration); que la
   validación cruzada se usó "para toda decisión" (la importancia por
   permutación usó una partición); que `evaluacion_final.py` era el único
   lector del test (también lo lee `preparar_demo.py`, sin calcular métricas).
5. Referencias a documentos que no viajan en la entrega (la bitácora) desde el
   informe final, los notebooks y `src/`; ahora apuntan a
   `reports/informe_final.md` o al reporte técnico.
6. La especificación todavía listaba R23 a R26; ahora son "aspectos añadidos"
   sin código, porque la tabla de requerimientos va de R1 a R22.
7. Código muerto e imports sin usar en el generador de apéndices y en las
   pruebas (pyflakes queda sin avisos).

El reporte del Módulo 2 sigue congelado y conserva sus erratas (el "AP ≈ 0,2",
el "≈40 %" y la frase de slowloris) como registro de lo calificado.

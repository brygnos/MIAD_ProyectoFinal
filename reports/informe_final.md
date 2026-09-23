# Detección de tráfico de red malicioso con aprendizaje de máquina
## Clasificación con desbalance de clases e interpretabilidad sobre CIC-IDS2017

> **Este es el informe resumido**, la versión de entrega para lectura rápida.
> Cuenta todo lo que se hizo; el detalle técnico de los experimentos (supuestos
> de cada modelo, protocolo, configuración de parámetros y evidencia de
> colinealidad) está en el **reporte técnico**
> ([reporte_tecnico_final.pdf](reporte_tecnico_final.pdf)). Los notebooks 01-06
> contienen todas las tablas y figuras ya ejecutadas, y los resultados
> numéricos completos están en CSVs versionados (`reports/resultados_*/`).

---

## 1. Contexto y problema

Una red corporativa produce millones de "conversaciones" entre computadores al
día. Casi todas son legítimas; unas pocas son ataques. Este proyecto responde,
con herramientas de ciencia de datos, tres preguntas sobre esa aguja en el
pajar:

1. **¿Qué distingue un ataque del tráfico normal?** (interpretabilidad)
2. **¿Qué tan bien se puede clasificar el TIPO de ataque cuando algunas clases
   son 200.000 veces menos frecuentes que el tráfico normal, y qué técnicas de
   manejo del desbalance ayudan?** (clasificación con desbalance)
3. **¿Un modelo entrenado únicamente con tráfico normal detecta ataques que
   nunca vio?** (detección de anomalías)

El problema se aborda como uno de **clasificación con desbalance de clases e
interpretabilidad** — no de ciberseguridad ofensiva — y cada término técnico
del dominio se explica en lenguaje llano.

## 2. Datos

### 2.1 El dataset CIC-IDS2017 en lenguaje llano

CIC-IDS2017 (Canadian Institute for Cybersecurity) simula **una semana de
tráfico** (lunes a viernes) en una red corporativa. Cada fila es un **flujo de
red**: una conversación entre dos computadores, resumida en ~77 medidas
numéricas calculadas automáticamente — cuántos paquetes se enviaron, de qué
tamaño, con qué ritmo, cuánto duró. Una etiqueta indica si el flujo fue
tráfico normal (`BENIGN`) o uno de 14 tipos de ataque: denegaciones de
servicio (saturar un servidor para dejarlo fuera de línea), escaneo de puertos
(tantear qué "puertas" de un servidor están abiertas), fuerza bruta de
contraseñas, ataques a aplicaciones web, botnet (una red de máquinas
infectadas que un atacante controla a distancia), infiltración (el atacante ya
está dentro de la red) y Heartbleed (un fallo célebre de 2014 que permite
robarle trozos de memoria a un servidor).

Tras la consolidación: **2.830.743 flujos**. El desbalance es severo en dos
niveles: 80,3% del tráfico es normal, y los 14 ataques van desde 231.073 casos
(DoS Hulk) hasta **11 casos** (Heartbleed) — una razón de 206.645 a 1 frente al
tráfico normal.

### 2.2 Calidad de los datos y limpieza aplicada

La inspección de los archivos reales confirmó las trampas documentadas del
dataset, y cada decisión de limpieza respondió a un diagnóstico:

| Problema encontrado | Magnitud | Decisión |
|---|---|---|
| Filas duplicadas exactas | 330.995 (11,7%) | Eliminadas: una fila repetida en entrenamiento y prueba se "acierta" de memoria (fuga de información) |
| Valores infinitos/faltantes en 2 features de tasa | 0,10% de las filas | Eliminadas (divisiones entre duración 0) |
| Duraciones negativas | 115 filas en el dataset crudo | Eliminadas (error de captura; 107 tras deduplicar — el resto cayó junto con los duplicados) |
| El valor −1 en `Init_Win_bytes_*` | 51% de las filas en `Init_Win_bytes_backward` (1.441.552) y 35% en `Init_Win_bytes_forward` (1.001.189) | No es un error: es un código de "no aplica"; se convirtió en un indicador binario |
| 8 features constantes y 45 pares con correlación > 0,95 en el entrenamiento (13 bloques) | — | Eliminadas/podadas: dos columnas idénticas se reparten la importancia y dañan la interpretación |

Resultado de la limpieza: **2.498.078 flujos y 71 features**. La poda por
correlación (71 → **48 features** descriptivas de comportamiento) se decidió
**únicamente con el conjunto de entrenamiento**, después de apartar el de
prueba.

## 3. Metodología

### 3.1 Preguntas de negocio

Las tres preguntas de arriba se validaron contra la evidencia del análisis
exploratorio antes de modelar. Dos ajustes salieron de esa validación: los tres
ataques web se agrupan en una familia **"Web Attack"** (por separado tienen
1.470 / 652 / 21 casos), y **Heartbleed (11) e Infiltration (36) quedan fuera
de la clasificación multiclase** — con tan pocos casos, cualquier métrica por
clase sería ruido. **SQL Injection no se evalúa como subtipo propio por falta
de muestras (21 casos): sus flujos viven dentro de la familia "Web Attack".**
Las clases excluidas se evalúan aparte, en el nivel binario y en el detector
de anomalías.

### 3.2 Diseño experimental

- **Un split, una sola vez:** 80% entrenamiento / 20% prueba, estratificado por
  clase, semilla 42. **El conjunto de prueba no se tocó durante todo el
  desarrollo**; se usó una única vez, al final (sección 4.4).
- **Validación cruzada estratificada de 5 particiones** sobre el entrenamiento
  para comparar técnicas, seleccionar el modelo y ajustar el punto de
  operación. La importancia por permutación, por su costo computacional, se
  midió con una sola partición.
- **Sin fuga de información:** el escalado se ajusta dentro del pipeline (solo
  con el tramo de entrenamiento de cada partición) y todo remuestreo — SMOTE
  (una técnica que crea ejemplos sintéticos de las clases raras interpolando
  entre casos reales vecinos) o submuestreo de la clase mayoritaria — ocurre
  dentro del pipeline de `imbalanced-learn`, nunca sobre los datos de
  validación.
- **Reproducibilidad:** semilla única (42), dependencias fijadas, cómputo
  pesado en scripts checkpointeados y notebooks que solo leen resultados
  compactos (corren en segundos en cualquier equipo).

### 3.3 Métricas (y por qué no se usa la exactitud)

Con 83% de tráfico normal, un "modelo" que diga *todo es normal* acierta el 83%
de las filas sin detectar un solo ataque. Por eso la exactitud (accuracy) está
excluida. Se reporta **macro-F1** (promedio simple del F1 de cada clase: las
clases raras pesan igual que las grandes), **recall y precisión por clase**,
**matrices de confusión** y **curvas precision-recall** con su área (AP).
Adicionalmente se reporta el **macro-F1 calculado solo sobre las clases de
ataque** (excluyendo BENIGN), que es la cifra más exigente.

## 4. Resultados

### 4.1 Pregunta 2 — Clasificación del tipo de ataque con desbalance

Antes de los experimentos se fijaron líneas base (Fase 2): un clasificador
trivial que siempre predice "Normal" — macro-F1 de 0,453 en binario y 0,082 en
multiclase, la demostración viva de por qué la exactitud no sirve aquí — y una
regresión logística sin corrección (binaria 0,921; multiclase 0,701). Sobre esa
referencia se cruzaron dos ejes en una matriz de 2 × 4 (capacidad del modelo ×
técnica de desbalance), con validación cruzada idéntica:

| macro-F1 (CV, media ± desv) | Sin corrección | Pesos de clase | SMOTE | Submuestreo + SMOTE |
|---|---|---|---|---|
| Regresión logística | 0,700 ± 0,014 | 0,543 ± 0,004 | 0,832 ± 0,005 | 0,650 ± 0,002 |
| **Árboles (HistGB)** | 0,948 ± 0,008 | **0,970 ± 0,002** | 0,966 ± 0,003 | 0,937 ± 0,046 |

*HistGB = HistGradientBoosting: cientos de árboles de decisión pequeños
encadenados, donde cada uno corrige los errores del anterior.*

Tres hallazgos:

1. **La capacidad del modelo pesó más que la técnica de desbalance.** El peor
   de los árboles supera a la mejor logística. Las clases "atascadas" (Bot y
   Web Attack, con AP de 0,22 y 0,30 en la línea base lineal) no estaban
   atascadas por el desbalance sino porque sus fronteras no son lineales: los
   árboles las recuperaron incluso sin corrección alguna (AP 0,54 y 0,85), y
   con pesos de clase quedaron en AP 0,91 y 0,99.
2. **Reponderar sin capacidad es contraproducente.** Los pesos de clase hunden
   a la logística (0,700 → 0,543): elevan el recall de las minoritarias a
   ~0,99, pero con precisión de 0,02-0,03 — una avalancha de falsas alarmas
   (~264.000 flujos normales marcados como ataque).
3. **El modelo elegido paga un costo mínimo en falsas alarmas:** árboles +
   pesos de clase deja 0,19% de los flujos benignos mal clasificados en
   validación cruzada.

### 4.2 Pregunta 1 — ¿Qué distingue un ataque del tráfico normal?

Se contrastaron dos miradas sobre el problema binario: los coeficientes de una
regresión logística estandarizada (el modelo legible) y la importancia por
permutación del modelo de árboles elegido (el modelo real). **Los dos rankings
coinciden en el núcleo temático — duración del flujo, ritmo entre paquetes
(features IAT) y tamaños de paquete — aunque no feature por feature**: la
logística concentra el crédito en el *ritmo* (tráfico "metrallador" de
herramientas automatizadas frente al ritmo irregular humano), mientras los
árboles lo reparten hacia los *tamaños de las respuestas del servidor*.

Un detalle metodológico valioso: **el indicador `Init_Win_bytes_forward_no_aplica`
— creado durante la limpieza para codificar el −1 de "no aplica" — resultó
informativo en ambos rankings.** Una decisión de limpieza se volvió señal: las
herramientas de ataque configuran distinto la apertura de la conexión TCP (el
"saludo" inicial con el que dos computadores acuerdan conversar) que las
aplicaciones normales.

**La verificación del puerto de destino.** `Destination Port` (la "puerta" del
servicio contactado) es el único identificador entre las 48 features, y quedó
en el puesto 2 de la importancia por permutación. En este dataset cada ataque
vive en su puerto canónico, así que un modelo podría estar aprendiendo el
montaje del experimento y no el comportamiento del ataque. La prueba —
reentrenar el campeón sin esa feature — fue central para validar la
interpretabilidad:

- El desempeño **no se derrumba**: macro-F1 de 0,970 a 0,950 (validación
  cruzada), con el recall de todas las clases prácticamente intacto. El modelo
  encuentra los ataques por su comportamiento.
- El costo se localiza en la **precisión** de las dos clases difíciles (Bot
  0,61 → 0,46; Web Attack 0,95 → 0,87): el puerto no sostenía la detección,
  pero ayudaba a descartar falsas alarmas.

### 4.3 Pregunta 3 — Detección de ataques nunca vistos

Un Isolation Forest (método que aísla cada punto con cortes aleatorios sobre
las features: lo raro queda aislado en pocos cortes, lo común necesita muchos)
se entrenó **únicamente con los 394.236 flujos benignos del lunes** (el único
día sin ataques) del conjunto de entrenamiento, con umbral fijado en el
cuantil 1% de sus propios scores. Evaluado sobre el resto de la
semana, el detector parte los ataques en dos mundos:

- **Los que ve — flujos estructuralmente raros:** Heartbleed (0,89),
  DoS slowloris (0,52), Infiltration (0,48). No es casualidad: son ataques cuyo
  flujo individual ya es anómalo (una extracción gigante de memoria, conexiones
  eternas). Y dos de ellas, **Heartbleed e Infiltration, son justo las clases
  que el clasificador supervisado tuvo que excluir por falta de datos**: el
  detector no supervisado complementa al supervisado donde este no llega, sin
  usar una sola etiqueta.
- **Los que no ve — el punto ciego del enfoque:** la fuerza bruta de
  contraseñas contra los servicios de archivos (FTP) y de acceso remoto (SSH),
  el escaneo de puertos y los ataques web y de botnet tienen recall ≈ 0. **Cada flujo individual de
  esos ataques parece una conexión normal; lo anómalo es el agregado — miles de
  conexiones casi idénticas en minutos — y un detector que examina flujos de a
  uno no puede verlo, por construcción.** Es un límite del enfoque, no un
  defecto de calibración.

Como detector general, la respuesta es negativa: 11,8% de recall global al 1%
de falsas alarmas. Como red de seguridad complementaria para ataques
estructuralmente raros y nunca etiquetados, aporta valor real. Un segundo
detector de contraste (Local Outlier Factor, entrenado con una submuestra por
su costo de predicción) confirmó la complementariedad desde el otro extremo:
ve la fuerza bruta contra SSH (recall 0,91) que el Isolation Forest no ve,
pero pierde Heartbleed y los DoS lentos. El costo operativo adicional es la
**deriva temporal**: el tráfico benigno del viernes en la tarde dispara 9,6%
de falsas alarmas (frente a ~1% los demás días).

### 4.4 Evaluación final sobre el conjunto de prueba (única pasada)

El punto de operación se cerró antes de tocar el test: alarma de Bot solo si
P(Bot) ≥ 0,999 (elegido con las probabilidades de validación cruzada del
entrenamiento — cada flujo puntuado por un modelo que no lo vio —, para
subir su precisión de 0,61 a ~0,93 sacrificando recall de 0,98 a ~0,68). Luego
el campeón se reentrenó con todo el entrenamiento y se evaluó **una sola vez**
sobre el 20% de prueba, en dos variantes:

| Test (única pasada) | macro-F1 | macro-F1 solo ataques |
|---|---|---|
| **Modelo final: con puerto + umbral de Bot** | **0,975** | **0,972** |
| Con puerto, regla estándar (elegir la clase más probable, sin umbral) | 0,967 | 0,964 |
| **Estimación conservadora: sin el puerto (regla estándar)** | **0,942** | **0,937** |

Lecturas obligadas de esta tabla:

- **Las cifras del test coinciden con las de validación cruzada** (0,967 vs
  0,970 ± 0,002 con puerto; 0,942 vs 0,950 ± 0,004 sin él): **no hubo
  sobreajuste** — la validación sobre el entrenamiento fue una estimación
  honesta.
- El resultado se encabeza deliberadamente con **ambas cifras**: 0,975/0,970
  con el puerto y **0,942-0,950 sin el artefacto del puerto**. La segunda es la
  **estimación conservadora, que no depende de que los servicios usen puertos
  canónicos** — y aun así debe leerse como desempeño sobre *este* dataset, no
  como garantía en una red real (sección 5).
- El umbral de Bot transfirió tal como se diseñó en la variante con puerto
  (precisión 0,947 en test, recall 0,728), pero **no transfirió en la variante
  sin puerto**: ese modelo nunca produjo P(Bot) ≥ 0,999 en el test y la regla
  eliminó las alarmas de Bot. Siguiendo el protocolo, no se reajustó nada tras
  ver el test; se reporta como lección: un umbral fijado en el extremo de la
  escala de probabilidad es frágil ante cambios del modelo.
- Falsas alarmas del modelo final sobre tráfico benigno: **0,12%**.
- Clases ultra-raras (cifras **ilustrativas**, sin significancia estadística):
  el detector binario (recall de ataque 1,000, precisión 0,994 en test) marcó
  como ataque **2 de 2** flujos de Heartbleed y **3 de 7** de Infiltration.
- El Isolation Forest replicó en el test lo visto en entrenamiento: recall
  global 11,8% al 1%, fuerte solo en flujos estructuralmente raros (Heartbleed
  1 de 2, Infiltration 4 de 7 — n mínima), ciego a los camuflados, y 9,6% de
  falsas alarmas el viernes en la tarde.

## 5. Limitaciones

1. **Clases ultra-raras.** Heartbleed (11 casos), SQL Injection (21) e
   Infiltration (36) no permiten conclusiones estadísticas por clase. Sus
   cifras se reportan siempre con la n al lado y como ilustrativas.
2. **Errores de etiquetado del dataset.** La literatura documenta problemas de
   etiquetado y generación de features en CIC-IDS2017 (Engelen et al. 2021;
   Rosay et al. 2022; Lanvin et al. 2023): parte del tráfico "benigno" podría
   contener ataques sin etiquetar — afecta en particular al detector no
   supervisado entrenado con el lunes "benigno" (mitigado con el umbral por
   cuantiles; imposible de descartar del todo).
3. **Deriva temporal del no supervisado.** El tráfico normal cambia entre días:
   la tasa de falsas alarmas del detector pasó de ~1% a 9,6% en un tramo del
   viernes. En producción exigiría recalibración periódica.
4. **Generalización más allá de CIC-IDS2017.** Es una red simulada de 2017, con
   ataques en puertos canónicos y una mezcla de tráfico específica. La variante
   sin puerto (0,942) es la estimación más honesta de transferencia, pero solo
   una evaluación sobre tráfico real permitiría afirmar desempeño en
   producción. El umbral de Bot, además, demostró ser sensible al cambio de
   variante del modelo.
5. **Detección por flujo individual.** Tanto el clasificador como el detector
   de anomalías miran flujos de a uno; los ataques cuya firma es el *agregado*
   (muchos flujos normales en ráfaga) solo son visibles para el supervisado
   porque tiene etiquetas. Features agregadas por ventana de tiempo son la
   extensión natural.

## 6. Conclusiones y trabajo futuro

1. **El tipo de ataque se puede clasificar con alta calidad pese al desbalance
   extremo:** macro-F1 de 0,975 en el test (0,972 solo ataques) con el modelo
   final, y 0,942 en la estimación conservadora sin el puerto. La coincidencia
   entre validación cruzada y test avala el protocolo.
2. **El diagnóstico correcto del desbalance importa más que la técnica:** las
   clases minoritarias "imposibles" para el modelo lineal no necesitaban más
   remuestreo sino más capacidad de modelo. Reponderar sin capacidad multiplica
   falsas alarmas.
3. **Los ataques se distinguen por comportamiento** — duración, ritmo entre
   paquetes, tamaños de paquete — y no solo por el puerto: quitar el único
   identificador cuesta 2-3 puntos de macro-F1, concentrados en la precisión de
   las clases difíciles.
4. **El no supervisado es un complemento, no un sustituto:** detecta sin
   etiquetas justo las familias que el supervisado no puede aprender por falta
   de datos, pero es ciego a los ataques camuflados y sensible a la deriva del
   tráfico normal.
5. **Trabajo futuro:** features agregadas por ventana temporal (para los
   ataques camuflados), calibración de probabilidades antes de fijar umbrales
   de operación, validación sobre una versión corregida del dataset
   (LYCOS-IDS2017) y sobre tráfico real.

## Referencias

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward
  generating a new intrusion detection dataset and intrusion traffic
  characterization.* ICISSP. (Dataset CIC-IDS2017:
  https://www.unb.ca/cic/datasets/ids-2017.html)
- Engelen, G., Rimmer, V., & Joosen, W. (2021). *Troubleshooting an intrusion
  detection dataset: the CICIDS2017 case study.* IEEE S&P Workshops.
- Rosay, A., et al. (2022). *Network intrusion detection: a comprehensive
  analysis of CIC-IDS2017.* ICISSP.
- Lanvin, M., et al. (2023). *Errors in the CICIDS2017 dataset and the
  significant differences in detection performances it makes.* CRiSIS 2022.
- Lemaître, G., Nogueira, F., & Aridas, C. K. (2017). *Imbalanced-learn.* JMLR.
- Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python.* JMLR.

# Preguntas de negocio — Detección de tráfico de red malicioso (CIC-IDS2017)

**Fase 0-1 · Documento para revisión.** Las tres preguntas candidatas se evaluaron
contra lo que el EDA ([notebooks/01_eda.ipynb](notebooks/01_eda.ipynb)) mostró que
los datos realmente soportan. Resumen del veredicto:

| # | Pregunta candidata | Veredicto |
|---|---|---|
| 1 | ¿Qué features distinguen ataque de tráfico normal? | ✅ **Sobrevive tal cual** |
| 2 | ¿Qué tan bien clasificamos el tipo de ataque, incluidos los raros? | ⚠️ **Sobrevive con ajustes** (3 clases no dan para métricas confiables) |
| 3 | ¿Un modelo no supervisado entrenado solo con tráfico normal detecta ataques no vistos? | ✅ **Sobrevive, como pregunta complementaria** |

---

## Contexto en una frase

Cada fila del dataset es un **flujo de red** (una "conversación" entre dos
computadores, resumida en 77 medidas numéricas) etiquetado como tráfico normal
(80,3%) o como uno de 14 tipos de ataque (19,7%), a lo largo de una semana
simulada de una red corporativa.

---

## Pregunta 1 — Interpretabilidad ✅

> **¿Qué características del tráfico de red distinguen un ataque del tráfico
> normal, y cuáles son las más informativas?**

**Por qué el dataset la soporta.**
- Hay 77 features numéricas medidas de forma homogénea en 2,8 millones de flujos;
  el EDA muestra diferencias visibles entre tráfico normal y de ataque en varias
  de ellas (duración, ritmo entre paquetes, tamaño de paquete), pero con
  solapamiento: ninguna feature separa sola, que es justo el caso donde un
  análisis multivariado aporta.
- El desbalance binario (80/20) es moderado y manejable con técnicas estándar.
- Condición previa que el propio EDA reveló: hay que podar 8 features constantes
  y 51 pares con |correlación| > 0,95 (37 features implicadas). Si no, dos
  columnas idénticas se "reparten" la importancia y la interpretación se daña.

**Método analítico.**
1. Limpieza aprobada + eliminación de features constantes y redundantes
   (~40-50 features finales).
2. Clasificación binaria (normal vs ataque) con modelos interpretables:
   regresión logística estandarizada (signo y magnitud de coeficientes) y árbol
   de decisión poco profundo (reglas legibles).
3. Contraste con un modelo de mayor capacidad (Random Forest) e **importancia por
   permutación**, para verificar que las features señaladas coinciden.
4. Entregable: ranking de features con explicación en lenguaje llano de por qué
   cada una tiene sentido (p. ej. "los ataques de fuerza bruta generan miles de
   conversaciones cortísimas e idénticas").

---

## Pregunta 2 — Clasificación multiclase con desbalance ⚠️

> **¿Qué tan bien podemos clasificar el tipo de ataque, y qué técnicas de manejo
> de desbalance mejoran la detección de los tipos poco frecuentes?**

**Qué soporta el dataset — y qué no.**
- ✅ 11 de las 14 clases de ataque tienen cientos a cientos de miles de ejemplos,
  suficientes para entrenamiento y validación cruzada estratificada.
- ❌ **Tres clases no soportan métricas por clase confiables:** Infiltration (36
  casos), SQL Injection (21) y Heartbleed (**11 casos en 2,8 millones**, ratio
  206.645:1 frente a BENIGN). Con validación cruzada de 5 particiones, Heartbleed
  aporta ~2 casos por partición: cualquier métrica sería ruido. Ninguna técnica
  de sobremuestreo fabrica información que no está.
- ⚠️ La deduplicación (necesaria para evitar fuga de información) reduce
  SSH-Patator en 45% y PortScan en 43%, pero ambas quedan con miles de casos:
  siguen siendo viables.

**Ajustes propuestos para que la pregunta sobreviva.**
- Agrupar los tres ataques web en una familia **"Web Attack"** (~2.100 casos tras
  deduplicar), que es además la agrupación natural del dominio.
- Reportar Infiltration y Heartbleed **por separado y sin promediar** (¿el modelo
  los detecta al menos como "ataque" en el nivel binario?), documentándolos como
  limitación del dataset, no barrerlos bajo un promedio.
- Evaluar con **macro-F1, recall por clase y matrices de confusión** — nunca
  accuracy global (decir "todo es normal" ya acierta 80%).

**Método analítico.** Comparar sistemáticamente: sin corrección → pesos de clase →
sobremuestreo SMOTE → submuestreo de BENIGN (imbalanced-learn ya está en
`requirements.txt`), con el mismo modelo base y validación cruzada estratificada
(RANDOM_STATE = 42), y medir qué técnica mejora el recall de las clases minoritarias
y a qué costo en falsos positivos.

---

## Pregunta 3 — Detección no supervisada de anomalías ✅ (complementaria)

> **¿Un modelo entrenado únicamente con tráfico normal puede señalar como
> "anómalos" los ataques, sin haber visto nunca un ataque etiquetado?**

**Por qué el dataset la soporta (hallazgo del EDA).**
- El lunes es **100% tráfico benigno** (529.918 flujos): un conjunto de
  entrenamiento natural que no requiere tocar las etiquetas de ataque.
- Los demás días aportan 14 tipos de ataque como conjunto de prueba, lo que
  permite responder la pregunta más interesante para el negocio: ¿detectaría
  ataques *nuevos*, no vistos? (los supervisados, por construcción, no pueden).

**Advertencias honestas.**
- La literatura documenta **errores de etiquetado** en CIC-IDS2017 (Engelen 2021;
  Lanvin 2023; Rosay 2022; ver README): parte del tráfico "normal" podría contener
  ataques sin etiquetar, lo que contamina el entrenamiento. Se documenta como
  limitación y se mitiga con el parámetro de contaminación del modelo.
- El tráfico benigno puede variar entre días (el modelo podría marcar como
  "anómalo" tráfico normal del viernes): hay que reportar la tasa de falsas
  alarmas por día, no solo la detección de ataques.

**Método analítico.** Isolation Forest y Local Outlier Factor (solo scikit-learn,
sin servicios externos), entrenados con el lunes, evaluados en martes-viernes con
recall por tipo de ataque y tasa de falsas alarmas sobre tráfico benigno.

---

## Decisiones de limpieza propuestas (pendientes de aprobación)

Derivadas del diagnóstico de calidad del EDA; ninguna está aplicada aún — el
Parquet consolidado conserva todas las filas:

1. Eliminar **330.995 filas duplicadas** (11,7%) para evitar fuga de información
   entre entrenamiento y prueba.
2. Eliminar las **2.867 filas (0,10%)** con Inf/NaN en `Flow Bytes/s` /
   `Flow Packets/s` (divisiones entre duración 0).
3. Eliminar las **115 filas** con duración negativa (error de captura).
4. Tratar el **−1** de `Init_Win_bytes_forward/backward` como código de "no
   aplica" (indicador binario aparte), no como número.
5. Eliminar las **8 features constantes** y podar las redundantes
   (|correlación| > 0,95) antes de modelar.
6. Splits **aleatorios estratificados** (cada ataque ocurre un solo día, así que
   un split temporal dejaría ataques sin representar en entrenamiento).

---

## Recomendación

Adoptar las **preguntas 1 y 2 (ajustada) como núcleo de la tesis** — juntas cuentan
una historia completa de clasificación con desbalance e interpretabilidad, que es
el marco del proyecto — y la **pregunta 3 como capítulo complementario**, que
aprovecha un hallazgo específico de estos datos (el lunes benigno) y diferencia el
trabajo. Ninguna candidata queda invalidada por los datos; la única reformulación
obligada es en la pregunta 2: para Heartbleed (11), SQL Injection (21) e
Infiltration (36) el dataset **no** permite conclusiones por clase, y decirlo
explícitamente es más defendible ante el jurado que un promedio que las oculte.

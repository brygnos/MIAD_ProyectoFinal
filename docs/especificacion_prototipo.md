# Especificación del prototipo — Tablero de detección de tráfico de red malicioso

> **Documento único de construcción.** Reemplaza al prototipo fachada y a la tabla de
> requerimientos como fuente de verdad para el desarrollo. Todo lo que aparece aquí se
> construye; lo que no aparece, no se construye.
>
> El proyecto analítico está **cerrado**: no se tocan resultados, cifras, figuras,
> checkpoints ni la evaluación del conjunto de prueba.

---

## 1. Qué se va a construir

Un **tablero web** (Streamlit) con URL pública donde un analista de seguridad carga un
archivo CSV de flujos de red sin etiquetar y obtiene, para cada flujo: si es ataque, de
qué tipo, con qué confianza, si además es anómalo, y por qué se marcó.

**Usuario directo:** analista de seguridad sin conocimientos profundos de redes ni de
programación.

**Necesidad:** recibe cientos de miles de flujos por día y no puede inspeccionarlos
manualmente. Necesita priorizar cuáles investigar, con una razón que pueda justificar
ante terceros, y sin acceder al contenido del tráfico por restricciones de privacidad.

**Escenario base (sin herramienta):** no hay priorización automática; revisar el tráfico
flujo por flujo es inviable y las reglas por firma no reconocen ataques nuevos.

**Modo de operación:** por lotes (el usuario carga un archivo). No es tiempo real.

---

## 2. Regla de calidad que gobierna todo: **autocontenido**

La retroalimentación del entregable anterior señaló tres veces el mismo problema: el
evaluador tuvo que saltar entre documentos para entender algo. **Cada pieza que
produzcamos debe entenderse por sí sola.**

En la práctica:

- El tablero **no** dice "ver R15": explica en pantalla qué hace y cómo leerlo.
- El informe final **no** dice "según la tabla de requerimientos": trae el texto.
- Ningún documento asume que el lector abrió otro archivo.
- Todo término técnico se explica en su primera aparición.

Esta regla aplica a la interfaz, al manual, al informe final y a las notas del equipo.

---

## 3. Requerimientos

Los 22 requerimientos aprobados. La columna **Estado** indica qué hay que construir:
*Cumplido* = ya demostrado en el análisis, el tablero solo lo expone. *Construir* = es
trabajo de esta fase.

### Negocio

| ID | Requerimiento | Criterio de aceptación | Estado |
|---|---|---|---|
| **R1** | Identificar y clasificar el tipo de ataque pese al desbalance extremo | Distingue tráfico benigno de 10 clases de ataque (los 3 ataques web agrupados en la familia "Web Attack") y entrega una clase por flujo. Heartbleed e Infiltration, con menos de 40 casos, se cubren en el nivel binario y con el detector de anomalías | Cumplido → exponer |
| **R2** | Reducir las falsas alarmas para disminuir la fatiga de alertas del SOC | Tasa de falsas alarmas ≤ 0,2% sobre el tráfico benigno | Cumplido → exponer |
| **R3** | Explicar en qué se basa el modelo, para que el usuario confíe en la alerta y la justifique | Muestra (a) las características más influyentes del modelo en general y (b) las que más pesaron en **cada alerta individual** | **Construir** |
| **R4** | Detectar comportamientos anómalos no etiquetados que el supervisado no puede aprender | Identifica las familias estructuralmente raras sin usar etiquetas, con recall > 0,4 al 1% de falsas alarmas. Se documenta que **no** detecta los ataques camuflados (fuerza bruta, PortScan, Bot) | Cumplido → exponer |
| **R5** | Demostrar valor frente al escenario sin herramienta | Supera de forma sustancial la línea base trivial (macro-F1 de referencia 0,082) y reduce a segundos la priorización de lotes cuya revisión manual tomaría cientos de horas | **Construir** (ver §5) |

### Desempeño

| ID | Requerimiento | Criterio de aceptación | Estado |
|---|---|---|---|
| **R6** | Desempeño suficiente para que las alertas sean accionables | Macro-F1 ≥ 0,94 en el conjunto de prueba | Cumplido |
| **R7** | Reproducibilidad de las cifras | Semilla fija (42) en todo el pipeline; mismas cifras en cada ejecución | Cumplido |
| **R8** | Integridad de la evaluación (anti-fuga) | Deduplicación antes del split; prueba evaluada una sola vez; escalado y remuestreo dentro del pipeline de validación cruzada; el desempeño en prueba cae dentro del intervalo de la validación cruzada | Cumplido |
| **R9** | Tiempos aceptables sin infraestructura especializada | Clasificación de hasta 50.000 flujos en menos de 30 segundos | **Construir y medir** |
| **R10** | Accesible sin que el usuario instale nada | Responde en navegador por URL pública; tras inactividad reanuda en menos de 1 minuto | **Construir** |
| **R11** | Detectar degradación por cambios en la distribución del tráfico | Se reporta la tasa de falsas alarmas por día y se documenta la deriva observada como señal de re-entrenamiento | Medido → exponer |

### Funcional

| ID | Requerimiento | Criterio de aceptación | Estado |
|---|---|---|---|
| **R12** | Recibir y validar el archivo del usuario | Acepta un CSV con esquema CICFlowMeter y reporta columnas faltantes o valores inválidos **antes de clasificar**, sin interrumpirse con un error | **Construir** |
| **R13** | Depuración de datos | Elimina duplicados y deja el dataset sin valores inválidos | Cumplido |
| **R14** | Clasificación supervisada por flujo | Entrega clase binaria y multiclase con su nivel de confianza por flujo | **Construir** |
| **R15** | Detección de anomalías con umbral ajustable | Marca como anómalos los flujos por debajo del umbral de score configurable | **Construir** |
| **R16** | Tablero navegable | Los resultados clave y su interpretación se alcanzan en ≤ 3 clics | **Construir** |
| **R17** | Alertas filtrables y exportación | Filtra la cola por tipo de ataque, nivel de confianza y marca de anomalía; exporta resultados y métricas en **CSV**, con el historial de la sesión | **Construir** |
| **R18** | Privacidad de los datos procesados | Ningún archivo del usuario persiste al terminar la sesión; el modelo opera solo con metadatos de flujo | **Construir y verificar** |
| **R19** | Integración con sistemas del SOC (SIEM) | La exportación CSV es la vía de esta iteración; la API queda propuesta | Deseable — **no construir** |

### Usabilidad

| ID | Requerimiento | Criterio de aceptación | Estado |
|---|---|---|---|
| **R20** | Operable sin conocimientos de programación | Un usuario ajeno completa el recorrido (cargar → revisar → exportar) sin asistencia | **Construir** |
| **R21** | Resultados comprensibles en lenguaje llano | Cada pantalla indica qué muestra y cómo leerlo; ningún término técnico sin explicación | **Construir** |
| **R22** | Compatibilidad de acceso | Funciona en navegadores de escritorio modernos; solo se necesita la URL. No optimizado para móvil | **Construir y verificar** |

### Requerimientos añadidos en respuesta a la retroalimentación

La evaluación de usabilidad pidió explicitar *"UI/UX, capacitación, recursos/licencias y
ambiente tecnológico"*. Estos cuatro se incorporan y se reportarán como ajustes
implementados.

| ID | Requerimiento | Criterio de aceptación |
|---|---|---|
| **R23** | Consistencia de interfaz (UI/UX) | Navegación uniforme entre pantallas; estados visibles de carga, vacío y error; ninguna acción deja al usuario sin señal de lo que ocurrió |
| **R24** | Capacitación del usuario | Manual de usuario con qué hace la herramienta, sus limitaciones y advertencias, requisitos previos, y al menos tres casos de uso paso a paso |
| **R25** | Recursos y licencias | Todas las dependencias son de código abierto con licencia compatible con uso académico; el dataset se cita según los términos de su proveedor |
| **R26** | Ambiente tecnológico | Documentado el entorno mínimo: para el usuario final, navegador de escritorio sin instalación; para reproducir el análisis, versión de Python, dependencias con versiones fijas y memoria requerida |

---

## 4. Las seis pantallas

El tablero combina **dos fuentes**: resultados fijos de la evaluación del modelo
(precalculados, no cambian) y el análisis en vivo del archivo que sube el usuario. Cada
pantalla debe dejar claro cuál de las dos está mostrando.

| Pantalla | Qué muestra | Se alimenta de | Requerimientos |
|---|---|---|---|
| **Panel de resumen** | Conteos del archivo cargado, alertas generadas, y la comparación de carga de revisión (§5) | CSV del usuario + métricas precalculadas | R5, R16 |
| **Clasificación** | Distribución de clases del archivo cargado; métricas por clase y matriz de confusión del modelo (precalculadas) | Modelo multiclase serializado + CSV de métricas del test | R1, R14, R6 |
| **Detección de anomalías** | Flujos marcados como anómalos, con control deslizante de umbral (0,5% – 2%) | Isolation Forest + umbrales por cuantiles | R4, R15 |
| **Interpretabilidad** | Qué mira el modelo en general; por qué se marcó una alerta concreta; resultado del experimento del puerto | Importancia por permutación (global) + explicador por flujo (local) | R3 |
| **Alertas** | Cola filtrable por tipo de ataque, nivel de confianza y marca de anomalía, con la explicación de cada flujo | Salida combinada del supervisado y del detector de anomalías | R17 |
| **Reportes** | Exportación en CSV de resultados y métricas; historial de la sesión | Tablas calculadas en sesión | R17 |

**No incluir:** columna de severidad (no existe una escala definida), exportación en PDF,
ni historial persistente entre sesiones.

---

## 5. Cómo se satisface R5 (utilidad vs. escenario base)

R5 tiene dos mitades que viven en lugares distintos.

**Mitad técnica → informe final y presentación, no el tablero.** La comparación contra
la línea base trivial (DummyClassifier, macro-F1 0,082 frente a 0,975 del modelo final).
Ya está calculada; no se construye nada.

**Mitad de negocio → Panel de resumen del tablero, calculada en vivo.** No compara
modelos: compara **carga de trabajo**. Con los conteos del archivo que sube el usuario:

> Flujos cargados: 500
> Sin la herramienta: 500 flujos por revisar uno por uno
> Con la herramienta: 37 alertas priorizadas
> **Reducción de la carga de revisión: 92,6%**

**Obligatorio junto a ese número**, una frase que declare el intercambio: sin
herramienta el analista revisa todo y no se le escapa nada, a costa de un trabajo
inviable; con herramienta revisa una fracción y acepta que el modelo pueda dejar pasar
algo. No es magia, es un intercambio.

---

## 6. Especificaciones técnicas

**Modelos serializados** (directorio `models/`, creado en esta fase):

- Clasificador multiclase campeón: HistGradientBoosting + pesos de clase, entrenado con
  todo el conjunto de entrenamiento.
- Clasificador binario (ataque sí/no).
- Isolation Forest entrenado solo con el tráfico benigno del lunes, con su
  StandardScaler y sus umbrales por cuantiles (0,5% / 1% / 2%).
- Junto a cada modelo, los metadatos que el tablero necesita: lista ordenada de las 48
  características, nombres de las clases, y la versión de scikit-learn usada.

**Sensibilidad de versión:** los artefactos de joblib dependen de la versión exacta de
scikit-learn. Congelar versiones en `requirements.txt` (`pip freeze`) y hacer que el
tablero verifique la versión al arrancar y advierta si no coincide.

**Archivo de demostración** (`data/demo/`):

- ~500 flujos tomados del **conjunto de prueba** (el modelo nunca los vio, así que la
  demostración es honesta), estratificados para incluir tráfico benigno y varios tipos
  de ataque, incluidos Bot y Web Attack.
- Con el **esquema completo de CICFlowMeter** (todas las columnas originales), no solo
  las 48 características: así se parece a lo que subiría un usuario real y sirve para
  probar la validación de entrada.
- **Sin la columna de etiqueta.** Las etiquetas verdaderas se guardan aparte, en un
  archivo separado que el tablero **nunca lee**, solo para verificar y narrar la
  demostración.
- Es material de demostración, no de evaluación: no se calcula ninguna métrica con él
  ni se ajusta nada.
- Verificar que el `.gitignore` permita ambos archivos (hay una regla global `*.csv`).

**Límites a verificar (R9):** hasta 50.000 flujos en menos de 30 segundos, con el
alojamiento gratuito que ofrece alrededor de 1 GB de memoria. Son cotas conservadoras:
si no se sostienen, hay que saberlo **antes** de prometerlas.

---

## 7. Explicaciones que deben aparecer en el producto

Por la regla de autocontenido, estas explicaciones van **en el tablero, en el manual y
en el informe final** — no en una sola parte.

**Cómo se fijan los umbrales por cuantiles** (la retroalimentación lo señaló como poco
claro):

> El detector se entrena solo con el tráfico del lunes, que es 100% benigno. Luego se le
> pide puntuar ese mismo tráfico conocido-normal, lo que produce una distribución de qué
> tan normal se ve cada flujo. El umbral se fija en el percentil 1 de esa distribución:
> por construcción, el 1% del tráfico que sabemos normal queda por debajo. Cualquier
> flujo de otro día que puntúe por debajo de ese corte se marca como anómalo. La ventaja
> es que el umbral no es un número arbitrario: es un **presupuesto explícito de falsas
> alarmas** — "acepto equivocarme en 1 de cada 100 flujos normales".

**El punto ciego del detector de anomalías:** ve lo estructuralmente raro (Heartbleed,
slowloris, Infiltration) y es ciego a los ataques camuflados (fuerza bruta, PortScan,
Bot), porque cada flujo individual parece normal y lo anómalo está en el conjunto, no en
el flujo. Es un límite del enfoque por flujo, y debe decirse en la propia pantalla.

**Cada métrica que se muestre** necesita una línea de qué significa. No basta con
"macro-F1 0,975".

**Métricas de negocio primero.** La retroalimentación pidió dos veces que los KPIs de
negocio no queden subordinados a las métricas del modelo. Encabezar con el KPI y poner
la métrica técnica como el medio: *"Fatiga de alertas: el modelo mantiene las falsas
alarmas en 0,12% del tráfico benigno"* — no al revés.

---

## 8. Diferencias frente al mockup entregado

El mockup se entregó con tres elementos que el tablero **no** tendrá. Esto debe quedar
**documentado explícitamente en el informe final** como ajustes implementados, no
omitido: declarado es un ajuste justificado; callado parece incumplimiento.

| En el mockup | En el tablero | Motivo |
|---|---|---|
| Columna de severidad en Alertas | Columna de marca de anomalía | No existe una escala de severidad definida ni justificada por criterio de dominio |
| Exportación en PDF | Solo CSV | Requiere librerías y tiempo adicionales; el CSV cubre la necesidad |
| Historial trazable de ejecuciones | Historial de la sesión | El alojamiento gratuito no garantiza persistencia entre reinicios |

Los valores numéricos que aparecen en el mockup son ilustrativos: no deben tomarse como
especificación.

---

## 9. Fuera de alcance — no construir

- Exportación en PDF · historial persistente entre sesiones · clasificación de severidad
- API REST de scoring / integración SIEM (R19: deseable, no verificable)
- Detección de ataques camuflados por vía no supervisada (requiere características
  agregadas por ventana de tiempo)
- Clasificación por subtipo de ataque web (XSS, SQL Injection: 652 y 21 casos)
- Calibración isotónica de probabilidades
- Ingesta de tráfico en tiempo real
- Optimización para dispositivos móviles

---

## 10. Cifras oficiales del proyecto

Únicas cifras válidas. **No inventar ni recalcular ninguna.**

| Concepto | Valor |
|---|---|
| Flujos en el dataset crudo | 2.830.743 |
| Flujos tras limpieza | 2.498.078 (88,25%) |
| Duplicados eliminados | 330.995 (11,69%) |
| Entrenamiento / prueba | 1.998.462 / 499.616 |
| Características usadas por el modelo | 48 |
| Clases del multiclase | 11 (benigno + 10 ataques) |
| Macro-F1 en prueba (modelo final, con umbral de Bot) | 0,975 |
| Macro-F1 solo ataques | 0,972 |
| Macro-F1 en prueba, regla estándar | 0,967 |
| Macro-F1 en prueba, sin el puerto de destino | 0,942 |
| Macro-F1 en validación cruzada | 0,970 ± 0,002 (0,950 ± 0,004 sin puerto) |
| Falsas alarmas del modelo final en prueba | 0,12% |
| Piso de referencia (clasificador trivial) | 0,082 |
| Umbral de operación de Bot | 0,999 → precisión 0,947 / recall 0,728 |
| Detector de anomalías, recall global al 1% | 11,8% |
| Recall por familia rara | Heartbleed 0,89 · slowloris 0,52 · Infiltration 0,48 |
| Falsas alarmas del detector de anomalías | ~1% típico · 9,6% el viernes en la tarde (deriva) |

# Guía de estilo de escritura del proyecto

Esta guía explica cómo escribimos los textos del proyecto (el tablero, los
notebooks, los comentarios del código y los README). Está pensada para que
cualquier persona, o una sesión de trabajo nueva que no conoce la historia del
proyecto, pueda escribir textos nuevos (por ejemplo, el manual de usuario) con
la misma voz. No viaja a la entrega.

## Contexto que hay que tener en cuenta

- Es el proyecto final de la Maestría en Inteligencia Analítica de Datos (MIAD).
  El jurado son científicos de datos, no expertos en ciberseguridad.
- El proyecto es un tablero web que clasifica tráfico de red (normal o alguno de
  los tipos de ataque) con el dataset CIC-IDS2017, y lo planteamos como un
  problema de clasificación con desbalance de clases e interpretabilidad.
- El usuario del tablero es un analista de seguridad: conoce redes, pero no
  programa ni es científico de datos.
- Todo se escribe en español.

## La idea general

Escribimos como habla una persona que explica su trabajo a un colega: frases
completas, conectadas entre sí, sin adornos y sin tono de anuncio. Preferimos
una oración un poco más larga y natural a varias frases cortas con estructuras
llamativas. Si una frase suena a eslogan, se reescribe.

## Qué evitar

1. **Rayas (—) y guiones largos para separar ideas.** Se reemplazan por comas,
   paréntesis, punto y seguido, o por "es decir".
2. **Flechas (→, ->) en la prosa.** "0,700 → 0,543" se escribe "pasa de 0,700 a
   0,543". En tablas de datos se pueden usar si ayudan, pero en texto corrido no.
3. **La estructura "no es X, es Y" y sus variantes** ("no X sino Y", "no es magia:
   es un intercambio", "una caída pequeña, no un derrumbe"). Se dice
   directamente lo que sí es.
4. **Títulos o rótulos con dos puntos que anuncian algo** ("La razón:", "La
   ventaja:", "Conclusión:", "Lectura general:", "Qué NO hay aquí, para que no
   lo busques:"). Se reemplazan por una oración normal: "El motivo es que…",
   "Es decir…", "En general…".
5. **Frases dramáticas o de efecto** ("dicho sin rodeos", "sin maquillar",
   "residuo honesto", "caso de libro", "el analista apagaría el sistema",
   "la prueba de honestidad"). Se cuenta el dato y ya.
6. **MAYÚSCULAS para enfatizar** ("SOLO", "DENTRO", "TODO el train", "NO",
   "SÍ"). Si hace falta énfasis se usa **negrilla**, y con moderación.
7. **Jerga en inglés cuando hay una palabra común en español**: "el mejor
   modelo" en lugar de "el campeón", "con checkpoints" en lugar de
   "checkpointeado". Se mantienen los términos técnicos establecidos (macro-F1,
   recall, SMOTE, test, pipeline), explicados la primera vez que aparecen.

## Qué usar

- **Conectores sencillos:** "es decir", "por eso", "por esta razón", "así que",
  "en este caso", "además", "el motivo es que", "como comparación".
- **Primera persona del plural** cuando se habla de decisiones del equipo:
  "usamos", "decidimos", "lo reentrenamos", "buscamos".
- **Segunda persona (tú)** cuando se le habla al usuario: "Aquí encontrarás…",
  "Aquí puedes ver…", "tu archivo", "haz clic en…", "¡Prueba con los archivos
  demo si no tienes uno a la mano!".
- **Aperturas de pantalla o de sección** que dicen qué hay ahí: "Aquí
  encontrarás…", "Aquí puedes ver…", "Aquí están…".
- **Guías de lectura** con el rótulo "**Cómo leer la tabla:**" seguido de la
  explicación de cada columna.
- **Notas** con "**Nota:**" al principio.
- **Cada término técnico se explica en lenguaje llano la primera vez** que
  aparece en una pantalla o sección, sin suponer que el lector ya lo conoce
  (por ejemplo: "un *flujo* es una conversación entre dos computadores,
  resumida en números").
- **Cifras:** decimales con coma (0,975) y miles con punto (499.616). Las cifras
  nunca se escriben de memoria: se copian de los resultados del proyecto.

## Ejemplos de antes y después

Los tres ejemplos vienen de textos que ya reescribimos. El primero lo reescribió
Bryan y es la mejor referencia de la voz del proyecto.

**1. Advertencia del Panel de resumen del tablero (reescrita por Bryan)**

Antes:

> **El intercambio, dicho sin rodeos:** sin herramienta, el analista revisa todo
> y no se le escapa nada — a costa de un trabajo inviable. Con herramienta,
> revisa una fracción priorizada y acepta que el modelo pueda dejar pasar algo.
> No es magia: es un intercambio, y conviene decidirlo con los ojos abiertos.

Después:

> Sin usar esta herramienta el analista **revisa absolutamente todo** e
> idealmente no se le escapa nada, a costa de un trabajo muy largo y muchas
> veces inviable si trabaja solo. Con esta herramienta **solo se revisa una
> fracción priorizada**, aceptando que el modelo pueda dejar pasar algo, pero
> con mucho más tiempo para indagar en esos casos puntuales sin tanta fatiga
> mental, es un intercambio y se debe tratar con cuidado, no hace todo el
> trabajo, pero lo puede facilitar mucho si se utiliza correctamente.

**2. Descripción de la pantalla Alertas del tablero**

Antes:

> Qué muestra: la cola de flujos de **tu archivo** que merecen revisión, con
> filtros para priorizar. Una *alerta* es un flujo que el modelo clasificó como
> algún tipo de ataque; la marca de *anomalía* señala, además, si su
> comportamiento se sale del patrón del tráfico normal según un segundo
> detector independiente.

Después:

> Aquí encontrarás la lista de flujos de **tu archivo** que vale la pena
> revisar, con filtros para priorizar. Una *alerta* es un flujo que el modelo
> clasificó como algún tipo de ataque. La marca de *anomalía* indica además si
> su comportamiento se sale del patrón del tráfico normal, según un segundo
> detector independiente.

**3. Explicación de la prueba del puerto (pantalla Interpretabilidad)**

Antes:

> **La prueba de honestidad con la puerta (puerto):** la segunda
> característica más influyente es la puerta del servicio contactado — y eso
> encendió una alarma metodológica, […] ¿El modelo detecta comportamiento o
> memorizó puertas? Se reentrenó **sin** esa característica: el desempeño pasó
> de 0,970 a 0,950 en validación y de 0,967 a 0,942 en la prueba — una caída
> pequeña, no un derrumbe. Conclusión: el modelo aprende **comportamiento**; la
> puerta solo le ayuda a descartar falsas alarmas en las clases más difíciles.

Después:

> **Prueba de la puerta (puerto de destino):** La segunda característica más
> influyente es la puerta del servicio contactado, y eso nos generó una duda
> metodológica, […] Para saber si el modelo detecta comportamiento o si
> simplemente memorizó puertas, lo reentrenamos **sin** esa característica y el
> desempeño pasó de 0,970 a 0,950 en validación y de 0,967 a 0,942 en el test.
> Es una caída pequeña, lo que indica que el modelo sí aprende
> **comportamiento** y que la puerta solo le ayuda a descartar falsas alarmas en
> las clases más difíciles.

## Cómo nombrar los elementos del tablero

Para que el manual coincida con lo que el usuario ve en pantalla, estos son los
nombres exactos (tomados del código del tablero). Los botones y controles se
escriben en **negrilla** y los textos que aparecen en pantalla, entre comillas.

- **Título de la barra lateral:** "Detector de tráfico malicioso".
- **Lista de pantallas** (control "Pantallas" de la barra lateral): Panel de
  resumen, Clasificación, Detección de anomalías, Interpretabilidad, Alertas y
  Reportes.
- **Carga de archivos** (sección "Cargar archivo"): el cargador se llama "CSV de
  flujos de red" y acepta archivos CSV con el formato de CICFlowMeter.
- **Demos:** debajo del cargador aparece "¿Sin archivo a la mano? Prueba con una
  demostración:" y los botones **Demo rica en ataques** y **Demo de proporción
  realista**. Cuando hay un archivo cargado, la barra lateral muestra "Archivo
  activo" con su nombre.
- **Detección de anomalías:** el control **Presupuesto de falsas alarmas (umbral
  del detector)** tiene tres valores: 0,5%, 1% y 2%.
- **Interpretabilidad:** el selector "Elige una alerta para ver qué pesó en esa
  decisión".
- **Alertas:** los filtros **Tipo de ataque**, **Confianza mínima** y **Marca de
  anomalía** (Todas, Solo anómalas, Solo no anómalas), la columna "Fila del
  archivo" y el botón **Descargar estas alertas en CSV**.
- **Reportes:** la sección "Descargas" (resultados completos, alertas con el
  filtro de la pantalla Alertas y **Métricas del modelo por clase (resultado
  fijo de la evaluación)**) y la sección "Historial de la sesión".

## Sobre las demos (para el manual)

Quien evalúe el proyecto va a usar las dos demos, así que son el camino
principal:

- Son muestras pequeñas del dataset CIC-IDS2017 tomadas del conjunto de prueba,
  es decir, de flujos que los modelos nunca vieron al entrenar.
- **Demo rica en ataques** (`data/demo/flujos_demo.csv`): 499 flujos, 39,9 % de
  ataque y 14 tipos de ataque. Muestra todo lo que el sistema detecta.
- **Demo de proporción realista** (`data/demo/flujos_demo_realista.csv`): 500
  flujos, 5,0 % de ataque y 10 tipos de ataque. Muestra cuánto trabajo de
  revisión le ahorra al analista.
- Las etiquetas verdaderas están en `data/demo/etiquetas_demo.csv` y
  `data/demo/etiquetas_demo_realista.csv`. El tablero no las lee; sirven para
  comprobar los resultados, y su columna `fila` coincide con la columna "Fila
  del archivo" del tablero.

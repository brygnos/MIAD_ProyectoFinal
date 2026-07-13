# Guía de estudio del proyecto — para explicarlo y defenderlo

> **Qué es este documento.** Material de estudio para el autor: un científico de
> datos sin background de redes ni ciberseguridad que debe poder explicar y
> defender cada decisión ante un jurado. **No es parte del informe de entrega**
> (ese es [reports/informe_final.md](../reports/informe_final.md)); aquí se
> permite ser largo, didáctico y repetitivo. Todo lo que se afirma sale del
> repo: código en `src/`, notebooks 01-06, informes y CSVs de resultados.
>
> Cómo estudiarlo: cada sección (2 a 7) termina con un bloque **"Pruébate"** de
> preguntas sin respuesta inmediata. Léela, cierra el documento, intenta
> responder, y revisa al final (sección 8).

---

## 1. La historia en una página

Una red corporativa produce millones de "conversaciones" entre computadores al
día. Trabajamos con **CIC-IDS2017**, un dataset que simula una semana de esas
conversaciones (2,8 millones de **flujos**, cada uno resumido en ~77 números)
donde cada flujo está etiquetado: tráfico normal (80,3%) o uno de 14 tipos de
ataque (19,7%). El problema NO lo tratamos como ciberseguridad, sino como lo
que es para un científico de datos: **clasificación con desbalance extremo**
(la clase más rara tiene 11 casos contra 2,3 millones de la mayoritaria; razón
206.645 a 1) **e interpretabilidad**.

Hicimos tres preguntas. **(1) ¿Qué distingue un ataque del tráfico normal?**
**(2) ¿Qué tan bien se clasifica el TIPO de ataque pese al desbalance, y qué
técnicas ayudan?** **(3) ¿Un modelo entrenado solo con tráfico normal detecta
ataques que nunca vio?**

El camino: limpiamos el dataset (11,7% de filas duplicadas —riesgo de que el
modelo "acierte de memoria"—, valores imposibles, códigos disfrazados de
números), apartamos un 20% de prueba **que nadie tocó hasta el final**, y
comparamos todo con validación cruzada sobre el 80% restante.

Tres hallazgos centrales:

1. **El "problema de desbalance" era en realidad falta de capacidad del
   modelo.** Con regresión logística, las clases Bot y Web Attack parecían
   imposibles (recall de 0,015 y 0,003) y ninguna técnica de desbalance las
   rescataba: los pesos de clase les subían el recall a ~0,99 pero con
   precisión de 0,02-0,03 (98 de cada 100 alarmas falsas). Al cambiar a árboles
   con boosting —sin corrección alguna— ambas revivieron. La lección: primero
   diagnostica si el modelo *puede* trazar la frontera; después corrige el
   desbalance. La mejor combinación fue **árboles + pesos de clase**.
2. **El modelo no depende del artefacto del puerto.** En este dataset cada
   ataque vive en su puerto "canónico" (el ataque web en el 80, SSH en el 22),
   así que un modelo podría aprender el montaje del experimento y no el
   comportamiento. Quitamos el puerto y el desempeño **no se derrumbó**
   (macro-F1 de 0,970 a 0,950 en validación): el recall de todas las clases se
   mantuvo; solo se encareció la precisión de las dos clases difíciles.
3. **Los dos detectores se complementan.** El clasificador supervisado es
   excelente en lo que tiene etiquetas, pero tuvo que excluir Heartbleed (11
   casos) e Infiltration (36) por falta de datos. Un Isolation Forest entrenado
   **solo con el tráfico benigno del lunes** detecta exactamente esas dos
   familias (y los DoS "lentos") sin haber visto una sola etiqueta — aunque es
   ciego a los ataques "camuflados" (fuerza bruta, escaneo de puertos, web,
   Bot), porque en esos ataques cada flujo individual parece normal y lo
   anómalo es el agregado.

Cifras finales sobre el conjunto de prueba (una sola pasada): **macro-F1 0,975**
con el modelo final (0,972 contando solo las clases de ataque) y **0,942 en la
estimación conservadora sin el puerto**; las cifras del test coincidieron con
las de validación cruzada (0,970→0,967; 0,950→0,942), la evidencia de que no
hubo sobreajuste ni fuga. Y una lección de humildad que reportamos sin
maquillar: el umbral de operación de Bot, afinado con entrenamiento, transfirió
perfecto en la variante con puerto (precisión de ~0,6 sin umbral en
validación a 0,947 en el test) pero falló en la
variante sin puerto (cero alarmas) — y como el protocolo prohíbe reajustar tras
ver el test, quedó reportado como lección sobre calibración de probabilidades.

> **Vocabulario mínimo antes de seguir** (la sección 5 los explica a fondo;
> esto es solo para que ninguna sigla te frene mientras lees):
> - **Recall** de una clase: de todos sus casos reales, qué fracción detectó el modelo.
> - **Precisión** de una clase: de todas las alarmas que dio el modelo para esa clase, qué fracción era correcta.
> - **Macro-F1**: promedio del F1 (equilibrio recall-precisión) de todas las clases, pesando igual a la más grande y a la más rara.
> - **AP**: área bajo la curva precision-recall; mide qué tan bien *ordena* el modelo a una clase, independiente del umbral elegido.
> - **Validación cruzada (estratificada, 5 particiones)**: entrenar 5 veces dejando fuera un quinto de los datos cada vez, y evaluar siempre sobre lo no visto, conservando las proporciones de cada clase.
> - **Boosting (de árboles)**: cientos de árboles de decisión pequeños encadenados, cada uno corrigiendo los errores del anterior.

---

## 2. Fundamentos de redes para entender los datos

### 2.1 El paquete: la unidad mínima

Cuando tu computador envía algo por la red —una foto, un clic, un correo— no lo
envía entero: lo parte en **paquetes**, pedazos pequeños de datos, cada uno con
su "sobre": dirección de origen, dirección de destino y números de orden para
rearmar todo al llegar. Piensa en enviar un libro por correo postal página por
página, cada página en un sobre numerado.

### 2.2 El flujo: la conversación completa (y por qué trabajamos con flujos)

Un **flujo** agrupa todos los paquetes de una misma conversación entre dos
computadores: mismo origen, mismo destino, mismo servicio, en una ventana de
tiempo. Si el paquete es el sobre, el flujo es *toda la correspondencia
intercambiada en esa conversación*, resumida: cuántos sobres fueron, de qué
tamaño, con qué ritmo, cuánto duró el intercambio.

¿Por qué el dataset trabaja con flujos y no con paquetes? Tres razones que
conviene poder recitar: (1) **volumen** — una semana de paquetes crudos es
inmanejable; los flujos comprimen millones de paquetes en 2,8 millones de
filas; (2) **privacidad** — el flujo no guarda el *contenido* de la
comunicación, solo su *forma* (tamaños, tiempos, conteos); (3) **son features
naturales para ML** — cada flujo ya es un vector de números comparables.

El costo de esa decisión reaparece al final del proyecto: un detector que mira
flujos **de a uno** no puede ver ataques cuya anomalía está en el *conjunto* de
flujos (miles de conexiones normales en ráfaga). Lo veremos con PortScan y la
fuerza bruta.

### 2.3 El puerto: la puerta del edificio

Una dirección IP identifica a un computador, como la dirección de un edificio.
Pero dentro del edificio hay muchas oficinas: el **puerto** es el número de la
puerta. El mismo servidor puede atender la web por la puerta 80 (o la 443 si es
cifrada), recibir archivos por la 21 (FTP) y aceptar administración remota por
la 22 (SSH). Los puertos existen para que un solo computador pueda ofrecer
varios servicios a la vez sin mezclar las conversaciones.

Por qué esto importa en el proyecto: `Destination Port` (la puerta a la que
tocaron) es una feature del dataset, pero **es un identificador, no un
comportamiento**. En este experimento el ataque web siempre toca la puerta 80 y
el de SSH siempre la 22 — en el mundo real nadie obliga a eso. De ahí el
experimento del puerto (sección 4.2 del informe final).

### 2.4 El handshake TCP y las banderas

TCP (el protocolo de la mayoría de las conversaciones) empieza con un saludo de
tres pasos, como una llamada telefónica: **SYN** ("¿aló, podemos hablar?"),
**SYN-ACK** ("sí, te escucho"), **ACK** ("listo, empiezo"). Las **banderas
(flags)** son marcas de un bit en cada paquete que señalan intenciones:

| Bandera | Significado en llano | Por qué puede delatar un ataque |
|---|---|---|
| SYN | "Quiero iniciar conversación" | Un escaneo de puertos son miles de SYN sin conversación después |
| ACK | "Recibido" | El pulso normal de toda conversación |
| FIN | "Termino cortésmente" | Su ausencia sugiere conexiones abandonadas |
| RST | "Cuelgo de golpe" | Puertas cerradas responden con RST: los escaneos los cosechan |
| PSH | "Entrega esto ya, sin esperar a llenar el buffer" | Común en tráfico interactivo |
| URG | "Datos urgentes" | Casi nunca se usa; su sola presencia es rara |
| ECE/CWR | Control de congestión | Rarísimas en la práctica |

Dato de NUESTROS datos (verificado en la fase de features): `Fwd PSH Flags`
resultó idéntica a `SYN Flag Count` (correlación 1,000) y `CWE Flag Count`
idéntica a `Fwd URG Flags`; por eso de cada par se conservó una sola
(`src/features.py`).

### 2.5 IAT: el ritmo delata a la máquina

**IAT** (*inter-arrival time*) es el silencio entre un paquete y el siguiente.
El dataset lo resume en media, mínimo, máximo y desviación, por dirección
(`Fwd IAT Mean`, `Bwd IAT Total`, `Flow IAT Max`...). La intuición que hay que
poder explicar: un humano navegando produce un ritmo *irregular* — lee, hace
clic, se distrae. Una herramienta automatizada dispara con *ritmo de
metralleta*: intervalos cortos y regulares. En nuestros resultados, las
features IAT dominan los coeficientes de la regresión logística (sección 1 del
notebook [04](../notebooks/04_interpretabilidad.ipynb)): el ritmo es una de las
señales más fuertes de automatización.

### 2.6 CICFlowMeter y las familias de features

**CICFlowMeter** es la herramienta del Canadian Institute for Cybersecurity que
convierte tráfico crudo capturado en las ~77 features de flujo del dataset.
Las familias, con su lectura en llano:

- **Fwd / Bwd** (*forward/backward*): la dirección. Fwd = lo que envía quien
  inició la conversación (el posible atacante); Bwd = lo que responde el otro
  (la posible víctima). Ejemplo: `Bwd Packet Length Mean` = tamaño promedio de
  las respuestas del servidor.
- **Longitudes de paquete** (`Packet Length Mean/Max/Variance`...): el tamaño
  de los sobres. Tamaños muy dispares o atípicos delatan tráfico no estándar.
- **IAT** (sección 2.5): el ritmo.
- **Conteos de banderas** (`SYN Flag Count`, `RST Flag Count`...): cuántas
  veces apareció cada intención en la conversación.
- **`Init_Win_bytes_forward/backward`**: la "ventana" TCP inicial — cuántos
  bytes está dispuesto a recibir cada lado sin esperar confirmación; es parte
  de cómo cada software configura la conexión al abrirla. Trae el valor **−1
  cuando no aplica** (no hubo handshake TCP que la anuncie). En la limpieza
  convertimos ese −1 en un indicador binario (`_no_aplica`) — y ese indicador
  terminó siendo señal en ambos rankings de interpretabilidad.
- **Active / Idle**: dentro de un flujo largo, cuánto tiempo hubo actividad en
  ráfagas y cuánto silencio total. Distingue "conversación fluida" de "conexión
  abierta pero muda" (marca de los DoS lentos).
- **Subflow**: sub-tramos del flujo; en estos datos resultaron alias exactos de
  los totales (se podaron por correlación 1,0).
- **Avg Bulk** (`Fwd Avg Bytes/Bulk`...): transferencias masivas; en los 8 CSV
  venían **constantes en cero** (las 8 features de varianza cero que se
  eliminaron).
- **`Flow Bytes/s` / `Flow Packets/s`**: la velocidad de la conversación. Aquí
  vivían todos los Inf/NaN del dataset (divisiones entre duración 0).

### Pruébate (sección 2)

1. ¿Por qué el dataset trabaja con flujos y no con paquetes, y qué punto ciego
   introduce esa decisión en la detección de ataques?
2. Explica con la analogía del edificio qué es un puerto, y por qué
   `Destination Port` es un "identificador" y no un "comportamiento".
3. ¿Qué significan SYN y RST, y qué patrón de esas dos banderas produce un
   escaneo de puertos?
4. ¿Qué mide el IAT y por qué el ritmo distingue humanos de máquinas?
5. ¿Qué significa el −1 de `Init_Win_bytes_forward` y qué hicimos con él en la
   limpieza?

---

## 3. Ficha de cada tipo de ataque

Para cada ataque: qué busca, cómo funciona, cómo se ve su tráfico, y cómo le
fue con NUESTROS dos detectores. Las cifras del supervisado son del **test**
(modelo final con puerto + umbral de Bot, única pasada,
[notebook 06](../notebooks/06_evaluacion_final.ipynb)); las del no supervisado
(Isolation Forest, "IF") son recall al umbral del 1%.

**Familia DoS/DDoS — dejar el servicio fuera de línea.** El atacante no quiere
robar nada: quiere que el servidor no pueda atender a nadie, como llenar un
restaurante de clientes falsos.

1. **DoS Hulk** (231.073 casos, la clase de ataque más grande). Bombardea el
   servidor web con peticiones HTTP a máxima velocidad desde una máquina.
   Tráfico: ráfagas masivas de flujos cortos, `Flow Packets/s` altísimo.
   Resultados: supervisado recall 0,999 / precisión 0,995; IF 0,24 — solo una
   parte de sus flujos es individualmente rara.
2. **DoS GoldenEye** (10.293). Variante del bombardeo HTTP que mantiene
   conexiones abiertas con keep-alive. Supervisado 0,998 / 0,982; IF ≈ 0,003:
   sus flujos se parecen demasiado a sesiones web normales.
3. **DoS slowloris** (5.796). La estrategia opuesta al bombardeo: abre muchas
   conexiones y las alimenta *lentísimo*, sin terminarlas nunca — **ocupar
   todas las mesas del restaurante sin ordenar jamás**. Tráfico: duración
   enorme, poquísimos bytes, silencios largos (Idle altos). Supervisado 0,991 /
   0,980; **IF 0,52**: cada flujo es raro en sí mismo, por eso el detector de
   anomalías sí lo ve.
4. **DoS Slowhttptest** (5.499). Primo de slowloris (peticiones HTTP
   deliberadamente incompletas o lentas). Supervisado 0,988 / 0,969; IF 0,16 al
   1% pero 0,77 al 2%: sus scores quedan justo al borde del umbral.
5. **DDoS** (128.027). El mismo bombardeo, pero **distribuido**: muchas
   máquinas atacando a la vez. Cada flujo individual es una petición corriente;
   la firma es el volumen coordinado. Supervisado 1,000 / 0,999; IF 0,03 —
   camuflado a nivel de flujo.

**Reconocimiento y robo de acceso.**

6. **PortScan** (158.930; la clase que más duplicados exactos tenía: −43% al
   deduplicar). **Probar todas las puertas del edificio** para ver cuáles
   abren: miles de SYN diminutos, respuestas RST de las puertas cerradas, casi
   cero datos transferidos. Supervisado 0,999 / 0,989; **IF 0,001**: cada
   "toque de puerta" individual parece un intento de conexión normal — el
   ejemplo de libro de que lo anómalo es el agregado. (El LOF, evaluado en
   entrenamiento, le vio 0,11.)
7. **FTP-Patator** (7.938). Fuerza bruta de contraseñas contra el servicio de
   archivos: **probar miles de llaves en la misma cerradura**. Cada intento es
   un login FTP de aspecto normal. Supervisado 1,000 / 1,000; IF 0,000.
8. **SSH-Patator** (5.897; −45% al deduplicar: sus intentos son casi idénticos
   entre sí). Igual, contra el acceso remoto SSH. Supervisado 0,998 / 1,000; IF
   0,000 — aunque el LOF (en entrenamiento) le vio 0,91: sus flujos comparten
   una densidad local peculiar. Fue además el caso de libro de "solo
   necesitaba el umbral": con la logística tenía recall 0,21 pero AP 0,80.
9. **Bot** (1.966). La máquina ya está infectada y "llama a casa"
   periódicamente para recibir órdenes: tráfico de bajo volumen que **imita
   deliberadamente la navegación normal**. Fue nuestra clase más difícil de
   principio a fin: AP 0,21 con la logística, precisión 0,61 con el campeón, y
   el objetivo del único ajuste de umbral del proyecto. Resultado final en
   test: **precisión 0,947 con recall 0,728** (con la regla de umbral); IF
   0,000. En la matriz de confusión, todas sus falsas alarmas provienen de
   BENIGN — se confunde con navegación, no con otros ataques.

**Ataques a la aplicación web** (agrupados en la familia "Web Attack";
supervisado sobre la familia: recall 0,993 / precisión 0,922; IF 0,000 para las
tres).

10. **Web Attack - Brute Force** (1.507). Adivinar las credenciales del login
    del sitio web: la misma cerradura, pero la puerta es un formulario.
11. **Web Attack - XSS** (652). Inyectar código malicioso en las páginas para
    que se ejecute en el navegador de otras víctimas (como dejar una nota
    trampa en el tablón de anuncios que todos leen).
12. **Web Attack - SQL Injection** (21 casos). Colar comandos de base de datos
    en un formulario para leer o alterar datos. **Con 21 casos no se evalúa
    como subtipo propio**: sus flujos viven dentro de la familia Web Attack y
    así está documentado en informe y código (`src/etiquetas.py`).

**Los ultra-raros** (excluidos del multiclase; evaluados aparte, siempre con la
n al lado — cifras ilustrativas, no estadística).

13. **Infiltration** (36 casos). El atacante ya está *dentro* (la víctima abrió
    un archivo trampa) y explora la red desde adentro. Detector binario en
    test: **3 de 7** marcados como ataque; IF en test: **4 de 7** — el no
    supervisado le ve más que el supervisado, coherente con que es
    comportamiento "raro" más que patrón aprendible con 29 ejemplos de
    entrenamiento.
14. **Heartbleed** (11 casos). Explota un fallo célebre (2014) del cifrado
    OpenSSL: **pedirle al servidor más memoria de la que debería entregar** —
    el servidor responde con trozos de su memoria interna. Tráfico: respuestas
    (Bwd) anormalmente enormes en una conexión cifrada. Binario en test: **2 de
    2**; IF en test: **1 de 2** (y 8 de 9 en la evaluación sobre
    entrenamiento): su flujo es tan raro que el detector de anomalías lo
    encuentra sin etiquetas.

### Pruébate (sección 3)

1. ¿Por qué el Isolation Forest ve a slowloris (0,52) pero no a DDoS (0,03), si
   ambos son denegación de servicio?
2. ¿Qué tienen en común PortScan, la fuerza bruta y Bot que los hace invisibles
   para un detector de anomalías por flujo?
3. ¿Por qué SQL Injection no tiene cifra propia en el multiclase y dónde
   quedaron sus 21 flujos?
4. Heartbleed e Infiltration: ¿quién los detecta mejor, el supervisado o el no
   supervisado, y con qué n hay que reportar cada cifra?
5. ¿Por qué SSH-Patator perdió el 45% de sus filas al deduplicar, y qué dice
   eso sobre cómo funciona ese ataque?

---

## 4. El proyecto paso a paso

### Fase 0-1 — Explorar antes de modelar

**Qué se hizo.** Inventario de los 8 CSV reales (~846 MB), inspección del
schema archivo por archivo, consolidación a Parquet
(1.834 MB → 664 MB de RAM con float32) y un EDA
([notebook 01](../notebooks/01_eda.ipynb)) que cuantificó el desbalance, la
calidad y la redundancia. Con eso se escribieron y evaluaron las preguntas de negocio (hoy integradas
en el informe detallado, Fase 0-1) y **se detuvo todo hasta aprobarlas**.

**Por qué así.** La regla del proyecto era no construir modelos hasta validar
que los datos soportan las preguntas. La alternativa descartada — modelar de
una vez — habría construido sobre un dataset con 11,7% de duplicados, columnas
con espacios, una columna repetida y tres clases con menos de 40 ejemplos, y
las decisiones habrían sido irreversibles a mitad de camino.

**Hallazgos que condicionaron todo lo demás:** cada tipo de ataque ocurre en
**un único día** (el lunes es 100% benigno), tres clases son inutilizables para
métricas por clase, y hay 8 features constantes + 51 pares con |r| > 0,95.

### Fase 2 — Limpieza, split único, features y líneas base

**Orden de operaciones y por qué importa:**

1. **Deduplicar ANTES del split.** Si la misma fila exacta cae en entrenamiento
   y prueba, el modelo la "acierta" de memoria y las métricas se inflan sin que
   el modelo sea mejor (fuga de información). El costo fue asimétrico
   (PortScan −43%, SSH-Patator −45%) y se aceptó documentándolo.
2. **Split estratificado aleatorio, NO temporal.** Como cada ataque vive en un
   solo día, un split "entrenar unos días / probar otros" dejaría tipos enteros
   de ataque sin un solo ejemplo de entrenamiento: el multiclase sería
   imposible por construcción. El estratificado garantiza ~20% de cada clase en
   prueba (hasta Heartbleed quedó 9/2). El costo honesto: es más optimista que
   un despliegue real, y así se declara en las limitaciones.
3. **El test se aparta UNA vez y se vuelve intocable.** Toda decisión posterior
   (features, técnica, modelo, umbral) se tomó solo con entrenamiento. Además
   `src/split.py` **se niega a regenerar el split** si los archivos existen —
   protección contra invalidar todos los resultados por un descuido.
4. **Poda de features decidida SOLO con entrenamiento** (71 → 48): los grupos
   con |r| > 0,95 se calcularon sobre una muestra del train y de cada grupo se
   conservó la representante más explicable. Hacerlo con todos los datos habría
   sido una fuga sutil: una decisión del pipeline informada por el test.
5. **Líneas base** ([notebook 02](../notebooks/02_baseline.ipynb)): el
   DummyClassifier (siempre "Normal") como piso — "acierta" 83% con recall 0 de
   ataques, el argumento vivo contra la accuracy — y la regresión logística
   (binaria 0,921; multiclase 0,701 de macro-F1) como referencia seria a
   superar.

**Qué habría pasado de hacerlo mal:** métricas infladas indetectables (fuga por
duplicados o por poda con test), o un multiclase imposible (split temporal), o
un "97% de accuracy" sin valor (sin piso ni métricas por clase).

### Fase 3 — La matriz de desbalance (2 modelos × 4 técnicas)

**Qué se hizo.** Cuarenta ajustes (8 combinaciones × 5 particiones):
{regresión logística, HistGradientBoosting} × {sin corrección, pesos de clase,
SMOTE, submuestreo de BENIGN + SMOTE}, todo con el MISMO split, la misma CV y
las mismas features ([notebook 03](../notebooks/03_desbalance.ipynb)).

**Por qué una matriz y no "probar SMOTE".** Para **atribuir cada mejora a su
causa**. Si solo hubiéramos probado técnicas de desbalance sobre la logística,
la conclusión habría sido "nada rescata a Bot y Web Attack" — falsa: lo que
faltaba era capacidad de modelo, no remuestreo. La matriz separa los dos
efectos: el peor árbol (0,937) superó a la mejor logística (0,832).

**Dos reglas anti-fuga que hay que saber defender:**
- **El remuestreo va DENTRO del pipeline de validación cruzada.** SMOTE crea
  puntos sintéticos interpolando vecinos. Si se aplicara antes de partir en
  folds, los sintéticos fabricados a partir de filas que caen en el fold de
  validación "contaminarían" el entrenamiento — el modelo validaría sobre
  información que ya vio en versión interpolada, inflando las métricas. Dentro
  del `imblearn.Pipeline`, el remuestreo solo toca el tramo de entrenamiento de
  cada fold.
- **El escalado también se ajusta dentro del pipeline**, por la misma razón:
  las medias y desviaciones se calculan solo con el tramo de entrenamiento.

**Elecciones de recursos documentadas:** SMOTE eleva las clases con < 20.000
casos hasta 20.000 (igualar todo a BENIGN habría fabricado ~14 millones de
filas sintéticas); el submuestreo baja BENIGN a 200.000 antes de SMOTE. La
combinación submuestreo+SMOTE en árboles resultó **inestable** (desviación
0,046: un fold cayó a 0,846) y se descartó por eso, no por la media.

**Resultado:** árboles + pesos de clase, macro-F1 **0,970 ± 0,002**, con 0,19%
de falsas alarmas sobre benigno en validación.

### Fase 4 — Interpretabilidad y no supervisado

**Pregunta 1.** Dos miradas sobre el problema binario: coeficientes de la
logística estandarizada (5 ajustes, media ± desviación) e importancia por
permutación del campeón, medida sobre 300.000 flujos de validación que el
modelo no vio ([notebook 04](../notebooks/04_interpretabilidad.ipynb)). El
puerto quedó #2 en la permutación → **experimento del puerto**: reentrenar el
campeón sin `Destination Port` (única feature identificadora entre las 48;
verificado que no sobrevivió `Protocol` ni puertos de origen). Resultado:
0,970 → 0,950, recall intacto, costo en precisión de Bot y Web Attack. La
alternativa descartada — reportar el ranking sin esta verificación — habría
dejado la interpretabilidad vulnerable a la crítica "tu modelo aprendió qué
puerto usa cada ataque en el laboratorio".

**Pregunta 3.** Isolation Forest entrenado SOLO con los 394.236 flujos benignos
del lunes presentes en el train; escalador ajustado solo con ellos; umbral =
cuantil 1% de los scores del propio lunes (con 0,5% y 2% como sensibilidad); LOF
como contraste ([notebook 05](../notebooks/05_no_supervisado.ipynb)). ¿Por qué
el cuantil en vez del parámetro `contamination` a ciegas? Porque reconoce
explícitamente la advertencia de la literatura: el "benigno" del lunes puede
contener ataques sin etiquetar. Evaluación sobre martes-viernes del train:
recall por tipo de ataque y **falsas alarmas POR DÍA** — y esa desagregación
reveló la deriva temporal (9,6% de falsas alarmas un tramo del viernes vs ~1%
el resto).

### Fase final — El test, una sola vez

**Orden estricto:** (1) verificar que ningún código lee `test.parquet` y que el
split no se regeneró; (2) fijar el punto de operación de Bot **solo con
probabilidades out-of-fold del train** (alarma de Bot solo si P(Bot) ≥ 0,999;
si no, segunda clase más probable); (3) reentrenar el campeón con TODO el train
(variantes con y sin puerto) y evaluar UNA vez sobre el test; (4) evaluar
también el binario (para las ultra-raras, con su n) y el Isolation Forest; (5)
**pase lo que pase, no reajustar nada** ([notebook 06](../notebooks/06_evaluacion_final.ipynb)).

Y pasó algo: el umbral de Bot transfirió perfecto con puerto (precisión 0,947 /
recall 0,728 en test, diseñado a ~0,93/0,68) pero en la variante sin puerto el
modelo reentrenado **nunca produjo P(Bot) ≥ 0,999** → cero alarmas de Bot →
macro-F1 0,888 con la regla. Se reportó tal cual, con su explicación (umbral
fijado en el extremo de la escala de probabilidad + cambio de modelo = frágil),
y la cifra honesta de esa variante es la de su regla estándar (argmax: elegir
la clase más probable): **0,942**. Reajustar el umbral
después de ver el test habría convertido la "evaluación única" en una segunda
ronda de ajuste — exactamente lo que el protocolo existe para impedir.

### Pruébate (sección 4)

1. ¿Por qué se deduplicó ANTES del split y qué pasaría con las métricas si no?
2. ¿Por qué un split temporal (entrenar lunes-jueves, probar viernes) habría
   roto el problema multiclase en este dataset?
3. Describe la fuga exacta que ocurriría si SMOTE se aplicara al dataset
   completo antes de la validación cruzada.
4. ¿Por qué la matriz de la Fase 3 tiene DOS ejes y qué conclusión falsa
   habríamos sacado con un solo eje?
5. En la fase final falló el umbral de Bot sin puerto. ¿Por qué NO se corrigió,
   si la corrección era obvia?

---

## 5. Las técnicas de ML explicadas

**Validación cruzada estratificada (5 particiones).** Parte el entrenamiento en
5 pedazos que conservan las proporciones de cada clase; entrena 5 veces dejando
un pedazo fuera y evalúa sobre ese pedazo. Cada flujo es evaluado por un modelo
que no lo vio, y las 5 cifras dan media ± desviación (por eso reportamos
"0,970 ± 0,002"). Por qué aquí: con clases de 1.500 casos, un solo split de
validación daría cifras con demasiada suerte/mala suerte; y la estratificación
garantiza que hasta las clases chicas estén en cada pedazo. Límite: cuesta 5
veces más cómputo, y con clases ultra-raras (Heartbleed: ~2 por fold) ni la
estratificación salva la métrica.

**Macro-F1 (y por qué no accuracy).** El F1 de una clase equilibra su precisión
y su recall; el macro-F1 **promedia los F1 de todas las clases con el mismo
peso**, tenga la clase 2 millones de casos o 1.500. La accuracy, en cambio,
pondera por frecuencia: nuestro piso (predecir siempre "Normal") logra 83% de
accuracy con CERO ataques detectados y macro-F1 de 0,082 en multiclase. En un
problema donde las clases raras son las importantes, la accuracy premia
ignorarlas. También reportamos el **macro-F1 solo sobre clases de ataque**
(0,972 en test), que quita el F1 casi perfecto de BENIGN del promedio: la cifra
más exigente.

**Curvas precision-recall y AP (y por qué no ROC con desbalance).** La curva PR
muestra, para cada umbral posible, el intercambio entre recall (¿qué fracción
de los ataques atrapo?) y precisión (¿qué fracción de mis alarmas es
correcta?); el AP es el área bajo esa curva. La ROC usa la tasa de falsos
positivos, cuyo denominador es la clase mayoritaria: con 2 millones de
benignos, 40.000 falsas alarmas son "solo" 2% de FPR y la ROC se ve
espectacular — pero si los positivos son 1.500, esas mismas 40.000 falsas
alarmas destruyen la precisión, y solo la curva PR lo muestra. El AP fue además
nuestra herramienta de diagnóstico: SSH-Patator con recall 0,21 pero **AP
0,80** significaba "el modelo la ordena bien, es cuestión de umbral"; Bot con
AP 0,21 significaba "el modelo no la separa: no hay umbral que la salve".

**Pesos de clase.** En vez de fabricar o borrar datos, cambia la función de
pérdida: equivocarse con una clase rara cuesta proporcionalmente más. Barato y
sin datos sintéticos. Límite (demostrado en nuestros resultados): si el modelo
no puede trazar la frontera, los pesos solo lo obligan a gritar "¡ataque!" más
veces — la logística con pesos subió el recall de Bot a 0,99 con precisión
0,02, y BENIGN cayó a recall 0,842 (~264.000 falsas alarmas). Con un modelo
capaz (árboles), los pesos fueron la mejor técnica (0,948 → 0,970).

**SMOTE.** Crea ejemplos sintéticos de la clase minoritaria interpolando entre
un caso real y sus vecinos más cercanos: un "punto intermedio" en el espacio de
features. Qué NO puede hacer: **fabricar información que no está** — no inventa
modos nuevos del ataque, solo rellena el espacio entre los casos que ya
existen; con 21 casos de SQL Injection no hay geometría que interpolar. Y sus
puntos sintéticos solo se usan para entrenar: las métricas siempre se calculan
sobre flujos reales. En nuestra matriz fue la mejor técnica para la logística
(0,700 → 0,832) y equivalente a pesos para los árboles.

**Submuestreo.** Borra aleatoriamente casos de la clase mayoritaria (BENIGN →
200.000) para que el entrenamiento no esté dominado por ella. Barato, pero tira
información: en árboles resultó la combinación inestable (un fold cayó a 0,846)
y en la logística la peor de las tres correcciones (0,650).

**Regresión logística vs HistGradientBoosting.** La logística es un modelo
**lineal**: su frontera de decisión es (en el espacio estandarizado) un
hiperplano — una "línea recta" generalizada; su gran virtud es que sus
coeficientes se leen (signo y magnitud). Los árboles con boosting construyen
cientos de árboles pequeños en secuencia, cada uno corrigiendo los errores del
anterior; cada árbol hace cortes tipo "¿`Flow Duration` > x? ¿y `Bwd Packet
Length Min` < y?" — la composición de cortes talla **regiones** arbitrarias del
espacio. Por eso los árboles ven lo que la logística no: Bot y Web Attack viven
en bolsillos del espacio de features que ninguna recta puede aislar (AP de
≈ 0,2 a 0,91 en Bot y a 0,99 en Web Attack al cambiar de modelo). "Hist" = las features se discretizan
en histogramas, lo que hace el entrenamiento rapidísimo (11 s el ajuste base en
2 millones de filas).

**Importancia por permutación.** Baraja una feature (rompe su relación con la
etiqueta) y mide cuánto cae el desempeño en datos que el modelo no vio; si cae
mucho, el modelo dependía de ella. Ventajas: es agnóstica al modelo y se mide
sobre validación (no sobre lo memorizado). Límite: con features
correlacionadas se reparte el crédito — por eso la poda previa de redundantes
(71→48) también protege esta lectura.

**Isolation Forest.** Intuición: para *aislar* un punto raro con cortes
aleatorios se necesitan pocos cortes; para aislar un punto metido en el montón,
muchos. El bosque hace cortes aleatorios y mide la profundidad promedio a la
que cada punto queda aislado: score bajo = raro. Se entrenó SOLO con benignos
del lunes: nunca vio un ataque. Límite estructural (nuestro hallazgo central de
la pregunta 3): evalúa flujos **de a uno**, así que los ataques cuya anomalía
es el agregado (PortScan, fuerza bruta, Bot) son invisibles por construcción.

**Umbral de operación y el caso Bot (incluida la falla).** Un clasificador
produce probabilidades; el *punto de operación* decide cuándo alarmar. Con AP
0,91, Bot permitía intercambiar recall por precisión: fijamos con datos de
entrenamiento (probabilidades out-of-fold) la regla "alarma de Bot solo si
P(Bot) ≥ 0,999", diseñada para precisión ~0,93 a cambio de recall ~0,68. En el
test, la variante con puerto cumplió el diseño (0,947 / 0,728). La variante sin
puerto no: su modelo, reentrenado con todo el train, **nunca produjo P(Bot) ≥
0,999**, y la regla dejó a Bot en cero. La explicación tiene nombre:
**calibración de probabilidades** — que P = 0,999 "signifique" lo mismo entre
modelos no está garantizado; los modelos de boosting tienden a empujar sus
probabilidades a los extremos de forma distinta según con qué features y datos
se entrenen, y un umbral clavado en el borde de la escala (0,999, sobre
probabilidades OOF guardadas en float16, además) es frágil ante cualquier
corrimiento. La respuesta correcta habría sido calibrar (p. ej. regresión
isotónica) o definir el umbral por cuantil de scores — trabajo futuro
declarado, porque tras ver el test no se toca nada.

### Pruébate (sección 5)

1. ¿Por qué la ROC "se ve bien" con desbalance extremo y qué muestra la curva
   PR que la ROC esconde?
2. AP 0,80 con recall 0,21 (SSH-Patator) vs AP 0,21 con recall 0,015 (Bot):
   ¿qué diagnóstico distinto implica cada combinación?
3. ¿Qué interpola SMOTE exactamente y por qué no puede "inventar" un modo nuevo
   de ataque?
4. Explica con la idea de "cortes" por qué HistGB separa a Bot y la logística no.
5. ¿Por qué falló el umbral de Bot en la variante sin puerto, y qué dos
   soluciones quedaron como trabajo futuro?

---

## 6. Guía de lectura de las 17 figuras

Todas en [reports/figures/](../reports/figures/). Formato: qué muestra → cómo
leerla → LA conclusión.

1. **`01_distribucion_clases.png`** (notebook 01). Barras horizontales del
   número de flujos por clase, **en escala logarítmica** (cada división = ×10).
   Sin la escala log, 12 de las 15 barras serían invisibles. LA conclusión: el
   desbalance es de dos niveles — BENIGN vs ataques, y ataques grandes vs
   Heartbleed (11), SQL Injection (21), Infiltration (36).
2. **`02_correlaciones_redundantes.png`** (notebook 01). Mapa de calor de
   correlaciones entre las features casi duplicadas (|r| > 0,999). Rojo intenso
   = miden lo mismo. LA conclusión: el dataset trae la misma información con
   varios nombres (`Subflow Fwd Bytes` ≡ `Total Length of Fwd Packets`); hay
   que podar antes de interpretar importancias.
3. **`03_normal_vs_ataque_features.png`** (notebook 01). Boxplots de 4 features
   (escala log) para tráfico normal vs ataque. Compara medianas y cajas. LA
   conclusión: hay separación visible pero con solapamiento — ninguna feature
   basta sola; se justifica un modelo multivariado.
4. **`04_pr_binaria.png`** (notebook 02). Curva precision-recall de la línea
   base logística binaria (validación cruzada). Eje x: fracción de ataques
   detectados; eje y: fracción de alarmas correctas; cada punto es un umbral
   posible. LA conclusión: la línea base binaria ya es fuerte — el reto del
   proyecto no era "ataque sí/no" sino el multiclase.
5. **`05_matriz_confusion_multiclase.png`** (notebook 02). Matriz de confusión
   de la logística multiclase, normalizada por fila (la diagonal es el recall
   de cada clase). Filas = clase real, columnas = predicha. LA conclusión: la
   diagonal es alta en las clases grandes y se desploma en las minoritarias —
   la brecha que la Fase 3 debía cerrar.
6. **`06_pr_minoritarias.png`** (notebook 02). Curvas PR de las 5 clases
   minoritarias con la línea base (AP en la leyenda). LA conclusión: el
   diagnóstico diferencial — SSH-Patator (0,80), Slowhttptest (0,85) y
   slowloris (0,91) son problema de umbral; Bot (0,21) y Web Attack (0,20)
   están genuinamente atascadas para el modelo lineal.
7. **`07_macro_f1_experimentos.png`** (notebook 03). Barras del macro-F1 de las
   8 combinaciones de la matriz, con barras de error (desviación entre folds) y
   la línea base 0,701 punteada. Colores: rojo = logística, verde = árboles. LA
   conclusión: todos los árboles superan a todas las logísticas — el eje del
   modelo pesó más que el del desbalance.
8. **`08_recall_minoritarias.png`** (notebook 03). Mapa de calor
   (combinaciones × clases) del recall medio; verde = alto, rojo = bajo. LA
   conclusión: la fila "logística + pesos" es verde (recall alto) pero
   engañosa — hay que cruzarla con la precisión, que se desploma; las filas de
   árboles son verdes de verdad.
9. **`09_confusion_mejor_combinacion.png`** (notebook 03). Matriz de confusión
   (out-of-fold) de árboles + pesos, normalizada por fila. LA conclusión:
   diagonal ≥ 0,98 en 9 de 11 clases; el único borrón es la columna de Bot, que
   recibe 967 benignos (su precisión 0,61).
10. **`10_pr_clases_atascadas.png`** (notebook 03). Curvas PR de Bot y Web
    Attack bajo tres modelos: logística base, árboles sin corrección, árboles +
    pesos. LA conclusión: la curva salta hacia la esquina superior derecha al
    cambiar de modelo, no al cambiar de técnica — la prueba visual de que era
    falta de capacidad.
11. **`11_coeficientes_logistica.png`** (notebook 04). Coeficientes
    estandarizados de la logística binaria (media ± desv entre 5 folds); rojo
    empuja hacia "Ataque", verde hacia "Normal". Magnitud = importancia
    comparable. LA conclusión: el ritmo (features IAT) domina la historia
    lineal; y el indicador `_no_aplica` creado en la limpieza aparece con
    coeficiente grande.
12. **`12_importancia_permutacion.png`** (notebook 04). Caída de macro-F1 al
    barajar cada feature en el modelo de árboles, sobre 300.000 flujos de
    validación. LA conclusión: `Flow Duration` primero y **`Destination Port`
    segundo** — la bandera roja que obligó al experimento del puerto.
13. **`13_experimento_puerto.png`** (notebook 04). Izquierda: macro-F1 con vs
    sin puerto (0,970 vs 0,950). Derecha: precisión de Bot, Web Attack y
    Slowhttptest en ambas variantes. LA conclusión: el desempeño global apenas
    se mueve (el modelo usa comportamiento); el costo real está localizado en
    la precisión de las clases difíciles.
14. **`14_recall_no_supervisado.png`** (notebook 05). Barras del recall por
    tipo de ataque del Isolation Forest al umbral 1% (verde = lo ve, rojo =
    invisible), con la n de cada clase. LA conclusión: los dos mundos — flujos
    estructuralmente raros (Heartbleed, slowloris, Infiltration) vs ataques
    camuflados en recall ≈ 0.
15. **`15_falsas_alarmas_por_dia.png`** (notebook 05). Barras de la tasa de
    falsas alarmas sobre benignos, por día/archivo, IF y LOF, con la línea del
    1% esperado. LA conclusión: la mayoría de los días quedan cerca del 1%,
    pero el viernes en la tarde el IF dispara 9,6% — la deriva temporal del
    tráfico normal es un costo real.
16. **`16_scores_no_supervisado.png`** (notebook 05). Densidades del score de
    anomalía por clase (más negativo = más raro). LA conclusión: las clases que
    el IF detecta tienen su masa separada de la de BENIGN; las invisibles están
    *dentro* de la distribución benigna — no es un problema de umbral, no hay
    dónde cortar.
17. **`17_confusion_test_final.png`** (notebook 06). Matriz de confusión del
    modelo final sobre el TEST (única pasada), normalizada por fila. LA
    conclusión: el patrón de la validación cruzada se reproduce en datos nunca
    vistos — la confirmación visual de que no hubo sobreajuste.

### Pruébate (sección 6)

1. ¿Por qué la figura 01 necesita escala logarítmica y qué se perdería sin ella?
2. ¿Qué "bandera roja" muestra la figura 12 y qué figura la resuelve?
3. En la figura 16, ¿qué distingue visualmente a un ataque detectable de uno
   invisible, y por qué eso implica que "no hay dónde cortar"?
4. ¿Qué par de figuras cuenta junta la historia "recall alto puede ser
   engañoso"?

---

## 7. Preguntas probables del jurado, con respuesta

*Respuestas en primera persona, como para decirlas en la sustentación.*

**1. ¿Por qué usar CIC-IDS2017 si la literatura documenta errores en él?**
Porque es el estándar público más usado para este problema, lo que hace mis
resultados comparables, y porque sus defectos están documentados (Engelen 2021,
Rosay 2022, Lanvin 2023), lo que me permitió tratarlos explícitamente: los
cuantifiqué en el EDA, los limpié cuando eran limpiables, y los declaré como
limitación cuando no (posibles etiquetas erróneas). Prefiero un dataset con
defectos conocidos y gestionados que uno privado sin auditoría. Como trabajo
futuro dejo la validación sobre LYCOS-IDS2017, la versión corregida.

**2. ¿Por qué no reportas accuracy?**
Porque con 83% de tráfico normal, predecir "todo es normal" da 83% de accuracy
con cero ataques detectados — lo demuestro con mi DummyClassifier en el
notebook 02. La accuracy pondera por frecuencia y aquí las clases importantes
son las raras. Uso macro-F1 (cada clase pesa igual), recall y precisión por
clase, y curvas precision-recall; y además reporto el macro-F1 solo sobre
ataques (0,972 en test), que es aún más exigente.

**3. ¿Cómo garantizas que no hubo fuga de información?**
Con cinco barreras verificables en el código: deduplicación antes del split
(sin filas repetidas entre train y test); test apartado una sola vez con un
script que se niega a regenerarlo; poda de features decidida solo con
entrenamiento; escalado y remuestreo dentro del pipeline de validación cruzada
(solo tocan el tramo de entrenamiento de cada fold); y umbral de operación
fijado con probabilidades out-of-fold del train. La prueba final: las cifras
del test coinciden con las de validación (0,970→0,967; 0,950→0,942) — si
hubiera habido fuga, el test habría salido peor que la validación.

**4. ¿No es sospechosamente alto un 0,97?**
Lo sería sin las verificaciones, por eso hice dos. Primera: la coincidencia
CV↔test descarta sobreajuste. Segunda: sospeché del propio dataset — el puerto
de destino es un artefacto del laboratorio — y reentrené sin él: 0,950 en
validación y 0,942 en test. Esa es mi estimación conservadora y la reporto
junto a la otra. Además, la literatura sobre este dataset reporta cifras de
este orden con modelos de árboles; lo distintivo de mi trabajo es la
verificación del artefacto, no el número alto.

**5. ¿SMOTE no está inventando datos falsos?**
SMOTE interpola: crea puntos intermedios entre un caso real de la clase
minoritaria y sus vecinos reales. No añade información nueva — no puede
fabricar un modo de ataque que no esté en los datos — pero le da al modelo más
densidad donde la clase ya vive, para que la frontera no la arrincone. Dos
salvaguardas en mi diseño: los sintéticos solo existen dentro del entrenamiento
de cada fold (jamás en validación ni test), y las métricas se calculan siempre
sobre flujos reales.

**6. ¿Por qué falló el umbral de Bot sin puerto y por qué no lo corrigió?**
Falló por calibración: fijé "alarma si P(Bot) ≥ 0,999" con probabilidades
out-of-fold de la variante con puerto y sin puerto, pero el modelo final sin
puerto, reentrenado con todo el train, nunca produjo probabilidades tan
extremas — un umbral en el borde de la escala es frágil ante cualquier
corrimiento de distribución. No lo corregí porque mi protocolo dice que el test
se evalúa una sola vez: si ajusto el umbral después de ver el test, el test
deja de ser test y se convierte en un segundo conjunto de validación. Preferí
reportar la falla con su explicación; la solución (calibrar probabilidades o
umbral por cuantiles) queda como trabajo futuro.

**7. ¿Qué pasaría con este modelo en una red real?**
Honestamente: no lo sé, y el informe lo dice. Tres razones para la cautela: es
una red simulada de 2017 con ataques en puertos canónicos (por eso mi cifra
conservadora sin puerto); el detector no supervisado mostró que el tráfico
normal deriva incluso entre días de la misma semana (9,6% de falsas alarmas un
viernes en la tarde), así que en producción haría falta recalibración
periódica; y los errores de etiquetado del dataset ponen un techo a lo que
puedo afirmar. Lo que sí defiendo es el *método*: el protocolo anti-fuga, la
verificación de artefactos y las dos cifras.

**8. ¿Por qué hay clases sin evaluar en el multiclase?**
Heartbleed tiene 11 casos e Infiltration 36 en 2,8 millones de flujos; con
validación cruzada de 5 particiones son ~2 y ~7 casos por partición — cualquier
métrica sería ruido, y promediarlas dentro del macro-F1 contaminaría la cifra
global con azar. Preferí excluirlas del multiclase, evaluarlas aparte en el
nivel binario (2 de 2 y 3 de 7 en test, siempre con la n al lado y marcadas
como ilustrativas) y — hallazgo que me gusta — mostrar que el detector no
supervisado las ve sin necesitar etiquetas.

**9. ¿En qué se diferencia esto de un antivirus o un IDS comercial?**
Un antivirus inspecciona archivos y un IDS de firmas busca patrones conocidos
escritos por expertos (como buscar caras de una lista de fotos). Mi sistema no
mira contenido ni firmas: aprende la *forma estadística* del comportamiento
(ritmos, tamaños, duraciones) desde datos etiquetados, y su componente no
supervisado busca lo que se desvíe de lo normal aunque nadie lo haya visto
antes. Son enfoques complementarios: el mío generaliza a variantes que cambian
la firma pero no el comportamiento, y a cambio no ofrece la explicación exacta
("es el malware X") que da una firma.

**10. ¿Por qué split aleatorio estratificado y no temporal, que sería más
realista?**
Porque en este dataset cada tipo de ataque ocurre en un único día: si entreno
con lunes-jueves y pruebo con viernes, el DDoS y el PortScan del viernes no
tendrían ni un ejemplo en entrenamiento — el multiclase sería imposible por
construcción del dataset, no por mérito del modelo. Acepto el costo: mi
estimación es más optimista que un despliegue real, y así está en las
limitaciones. La pregunta temporal la respondo por otra vía: el detector no
supervisado entrena con el lunes y se prueba en los demás días.

**11. ¿Por qué eliminó el 11,7% de los datos (duplicados)? ¿No es tirar
información?**
Es tirar redundancia exacta, no información: eran filas idénticas en las 78
columnas, generadas por ataques automatizados que repiten el mismo flujo miles
de veces. El riesgo de conservarlas es concreto: la misma fila caería en
entrenamiento y en prueba, y el modelo "acertaría" por memoria — mis métricas
se inflarían sin que el modelo mejorara. El costo fue asimétrico (PortScan
−43%, SSH-Patator −45%) y lo documenté antes de aplicarlo, con aprobación
explícita.

**12. ¿Cómo sé que su modelo no aprendió "qué puerto usa cada ataque en su
laboratorio"?**
Esa es exactamente la crítica que me hice: el puerto quedó #2 en la importancia
por permutación. Por eso reentrené el campeón sin `Destination Port` (verifiqué
que era el único identificador entre mis 48 features): el macro-F1 pasó de
0,970 a 0,950 y el recall de todas las clases quedó intacto — el modelo
encuentra los ataques por comportamiento; el puerto solo le ayudaba a descartar
falsas alarmas en las dos clases difíciles. Reporto ambas cifras siempre juntas.

**13. ¿Por qué árboles con pesos de clase y no una red neuronal?**
Por tres restricciones del proyecto: interpretabilidad (el jurado y el caso de
uso piden explicar qué mira el modelo; con árboles tengo importancia por
permutación coherente con un modelo lineal de contraste), reproducibilidad (el
entregable corre desde un ZIP con scikit-learn, sin GPU ni servicios externos)
y evidencia: los árboles ya saturan el problema (0,97 en test) con 11 segundos
de entrenamiento base; una red añadiría opacidad y costo sin margen visible de
mejora en este dataset.

**14. ¿El Isolation Forest no es inútil con 11,8% de recall?**
Como detector general, sí — y así lo digo. Su valor está en *qué* 11,8%:
detecta sin una sola etiqueta justo las familias que mi supervisado no puede
aprender por falta de datos (Heartbleed, Infiltration) y los DoS lentos. Es un
complemento barato, no un sustituto: el supervisado cubre lo conocido, el no
supervisado vigila lo estructuralmente raro, y su punto ciego (los ataques
camuflados, donde cada flujo parece normal) está declarado como límite del
enfoque por-flujo, con la extensión natural — features agregadas por ventana de
tiempo — como trabajo futuro.

**15. Si el "benigno" del lunes puede contener ataques sin etiquetar, ¿no está
entrenando su detector con datos contaminados?**
Es posible, y está declarado como limitación citando la literatura que lo
documenta. Dos mitigaciones: fijé el umbral por cuantiles de los scores del
propio lunes (asumo explícitamente que hasta ~1% de mi "normal" puede ser
raro), y contrasto tres umbrales (0,5%, 1%, 2%) para mostrar sensibilidad. La
señal tranquilizadora: el lunes del test — flujos benignos nunca vistos — dio
0,98% de falsas alarmas, casi exactamente el 1% de diseño.

**16. ¿Puedo reproducir sus resultados en mi portátil?**
Sí, en tres niveles: leer los notebooks ya ejecutados y el informe (cero
cómputo); re-ejecutar los notebooks 03-06, que leen CSVs de kilobytes
versionados en el repo (segundos en cualquier máquina); o reproducir todo desde
los CSV crudos con los 8 scripts en orden (semilla 42 en todo; ~2 horas en mi
máquina de 24 núcleos, más en una modesta, ~8 GB de RAM; los pasos pesados
están checkpointeados y no se repiten si se interrumpen).

**17. ¿Qué fue lo que más le cambió la cabeza en el proyecto?**
Que el "problema de desbalance" no era de desbalance. Gasté una fase entera en
técnicas de remuestreo sobre la logística y ninguna rescató a Bot ni a Web
Attack; el diagnóstico correcto estaba en el AP (0,21 y 0,20: el modelo ni
siquiera las ordenaba). Cambiar de familia de modelo, sin corrección alguna,
las revivió. La moraleja metodológica que defendería en cualquier proyecto:
antes de tratar el síntoma con remuestreo, verifica si tu modelo puede
representar la frontera.

### Pruébate (sección 7)

1. Un jurado dice: "83% de tráfico normal, tu modelo acierta 97%... apenas
   mejor que adivinar". ¿Cuáles son los DOS errores de esa frase?
2. ¿Cuál es la evidencia numérica concreta de que no hubo sobreajuste?
3. ¿Qué responderías, en una frase, a "¿esto funcionaría en mi empresa?"
4. ¿Por qué NO corregir el umbral de Bot tras ver el test, si era una línea de
   código?
5. ¿Cuál es la cifra "conservadora" del proyecto, de dónde sale, y por qué es
   la honesta para hablar de generalización?

---

## 8. Respuestas de los "Pruébate"

### Sección 2 — Fundamentos de redes

1. Flujos porque comprimen el volumen, protegen la privacidad (forma, no
   contenido) y ya son vectores de features. Punto ciego: un detector por-flujo
   no ve ataques cuya anomalía es el *conjunto* de flujos (PortScan, fuerza
   bruta, Bot) — cada flujo individual parece normal.
2. La IP es la dirección del edificio; el puerto, el número de la puerta de
   cada servicio (80 web, 22 SSH). Es identificador porque dice *a qué puerta
   tocaron*, no *cómo se comportó* la conversación — y en el laboratorio cada
   ataque siempre toca la misma puerta, cosa que en el mundo real no está
   garantizada.
3. SYN = "quiero iniciar conversación"; RST = "cuelgo de golpe / puerta
   cerrada". Un escaneo produce miles de SYN sin conversación posterior y
   cosecha RST de las puertas cerradas.
4. IAT es el silencio entre paquetes consecutivos. Los humanos producen ritmo
   irregular (leen, dudan, hacen clic); las herramientas disparan a intervalos
   cortos y regulares — ritmo de metralleta.
5. Es un código de "no aplica" (no hubo handshake TCP que anuncie la ventana),
   no un número. En la limpieza se creó el indicador binario
   `Init_Win_bytes_forward_no_aplica` y el −1 pasó a 0; el indicador terminó
   siendo señal en ambos rankings de interpretabilidad.

### Sección 3 — Ataques

1. Slowloris deja conexiones eternas casi sin datos: cada flujo individual es
   estructuralmente raro. En DDoS cada flujo es una petición HTTP corriente; lo
   anómalo es que lleguen miles coordinadas — invisible mirando flujos de a uno.
2. Que su anomalía está en el agregado: cada flujo individual (un toque de
   puerta, un intento de login, un "llamado a casa") parece una conexión
   normal. Recall del IF ≈ 0 en los tres casos.
3. Tiene solo 21 casos: sin muestras para evaluarla como subtipo. Sus flujos
   quedaron dentro de la familia "Web Attack" (documentado en
   `src/etiquetas.py` y en el informe final).
4. Heartbleed: binario 2 de 2, IF 1 de 2 en test (8 de 9 en la evaluación sobre
   entrenamiento). Infiltration: binario 3 de 7, IF 4 de 7 — al no supervisado
   le va relativamente mejor ahí. Todas las cifras se reportan con su n y como
   ilustrativas: con n = 2 y n = 7 no hay significancia estadística.
5. Porque la herramienta repite miles de intentos de login casi idénticos, que
   generan flujos exactamente iguales → 45% de duplicados exactos. Confirma que
   es un ataque automatizado de repetición.

### Sección 4 — El proyecto paso a paso

1. Una fila idéntica puede caer a la vez en entrenamiento y prueba: el modelo
   la "acierta" de memoria y las métricas se inflan sin mérito (fuga). Con
   11,7% de duplicados —hasta 45% en algunas clases— la inflación habría sido
   sustancial e indetectable.
2. Porque cada ataque ocurre en un único día: el día reservado para prueba
   contendría tipos de ataque con cero ejemplos de entrenamiento. El multiclase
   fallaría por construcción del dataset, no por el modelo.
3. SMOTE crea sintéticos interpolando vecinos. Aplicado antes de partir en
   folds, fabrica puntos a partir de filas que luego caen en validación: el
   modelo entrena con versiones interpoladas de los datos con los que será
   evaluado → métricas infladas. Dentro del pipeline, solo se remuestrea el
   tramo de entrenamiento de cada fold.
4. Dos ejes (capacidad × técnica) para atribuir cada mejora a su causa. Con un
   solo eje (técnicas sobre la logística) habríamos concluido "Bot y Web Attack
   son imposibles" — cuando lo que faltaba era capacidad de modelo: el peor
   árbol (0,937) superó a la mejor logística (0,832).
5. Porque el protocolo de evaluación única existe precisamente para eso:
   ajustar cualquier cosa después de ver el test lo convierte en un segundo
   conjunto de validación y las cifras dejan de ser una estimación honesta de
   datos nuevos. Se reportó la falla con su explicación y la corrección quedó
   como trabajo futuro.

### Sección 5 — Técnicas

1. La ROC usa la tasa de falsos positivos, cuyo denominador es la clase
   mayoritaria: 40.000 falsas alarmas entre 2 millones de benignos son "2%" y
   la curva se ve excelente. La PR usa la precisión, cuyo denominador son las
   alarmas: esas mismas 40.000 falsas alarmas contra 1.500 positivos reales
   hunden la curva. Con desbalance, la PR muestra el dolor real del analista.
2. AP alto + recall bajo (SSH-Patator) = el modelo ordena bien y el umbral la
   ahoga: se arregla reponderando o moviendo el umbral. AP bajo + recall bajo
   (Bot en la logística) = el modelo no la separa: ningún umbral la salva, hace
   falta otro modelo.
3. Interpola puntos intermedios entre un caso minoritario real y sus vecinos
   reales en el espacio de features. Solo rellena el espacio entre lo que ya
   existe: no puede crear un modo de ataque ausente de los datos (con 21 casos
   no hay geometría que rellenar).
4. La logística solo puede trazar un hiperplano (una "recta" generalizada). El
   boosting compone cientos de cortes tipo "¿feature > x?" que tallan regiones
   arbitrarias: puede aislar los bolsillos del espacio donde viven Bot y Web
   Attack. Evidencia: AP de ≈ 0,2 a 0,91 (Bot) y a 0,99 (Web Attack) al
   cambiar de modelo, sin tocar el desbalance.
5. Por calibración: el umbral 0,999 se fijó en el extremo de la escala con
   probabilidades OOF, y el modelo sin puerto reentrenado con todo el train
   nunca produjo probabilidades tan extremas → cero alarmas. Soluciones futuras:
   calibrar probabilidades (p. ej. isotónica) o definir el umbral como cuantil
   de los scores en lugar de un valor absoluto.

### Sección 6 — Figuras

1. Porque las clases van de 2,3 millones a 11 casos: en escala lineal, 12 de 15
   barras serían píxeles invisibles y el hallazgo central (el desbalance de dos
   niveles) desaparecería de la vista.
2. La 12 muestra `Destination Port` como #2 en importancia por permutación (la
   bandera roja de posible artefacto); la 13 la resuelve: sin el puerto el
   macro-F1 apenas baja (0,970→0,950) y el costo se localiza en la precisión de
   Bot/Web Attack.
3. Los detectables tienen su masa de scores separada de la distribución de
   BENIGN; los invisibles están *dentro* de ella. Si las densidades se
   solapan por completo, ningún umbral separa: no es un problema de
   calibración sino de representación (el flujo individual no contiene la
   señal).
4. La 8 y la 9 (o la 8 con las tablas de precisión del notebook 03): la fila
   "logística + pesos" del mapa de recall es toda verde, pero la precisión
   correspondiente es 0,02-0,03 — recall alto con precisión desplomada es una
   avalancha de falsas alarmas, no un buen detector.

### Sección 7 — Jurado

1. Primero, compara accuracy contra el 83% cuando la métrica del proyecto es
   macro-F1 (el "piso" de accuracy 83% tiene macro-F1 0,082 en multiclase).
   Segundo, "97%" no es accuracy: es macro-F1, donde cada clase — incluida una
   de 1.500 casos — pesa igual que BENIGN; un modelo que ignore las raras no
   llega ni cerca.
2. La coincidencia CV↔test con la misma regla de decisión: 0,970 ± 0,002 en
   validación cruzada vs 0,967 en test (con puerto), y 0,950 ± 0,004 vs 0,942
   (sin identificadores). Si hubiera habido fuga o sobreajuste, el test habría
   quedado por debajo de esos intervalos.
3. "No lo sé sin probarlo en tu tráfico — y desconfía de quien te diga otra
   cosa: mi cifra conservadora sin el artefacto del puerto es 0,942 sobre esta
   red simulada, y el tráfico normal deriva incluso entre días de la misma
   semana."
4. Porque el valor del test es ser una única mirada a datos nunca usados para
   decidir nada; corregir después de mirarlo lo convierte en validación y la
   cifra final deja de ser creíble. La honestidad del 0,975 con puerto depende
   de haber dejado el 0,888 sin maquillar al lado.
5. **0,942** (macro-F1 en test, variante sin identificadores, con la regla
   estándar de elegir la clase más probable; su
   CV fue 0,950 ± 0,004). Sale de reentrenar el campeón sin `Destination Port`
   — el único identificador del dataset. Es la honesta porque no depende de que
   cada ataque use su puerto canónico, cosa que solo está garantizada en el
   laboratorio; aun así es desempeño sobre CIC-IDS2017, no una garantía en red
   real.

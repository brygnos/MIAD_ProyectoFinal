# Pruebas de los requerimientos

Cada prueba verifica **un requerimiento de la tabla entregada (R1–R22)**,
siguiendo su columna «Prueba prevista». El nombre de cada función empieza por
el código del requerimiento (`test_R12_...`) y su docstring cita la prueba
prevista y el criterio de aceptación, de modo que la salida del comando sirve
como evidencia fila por fila al diligenciar la tabla.

## Un solo comando

Desde la **raíz del proyecto**, con el entorno de la app activo:

```bash
python -m pytest -v
```

Tarda unos 10 segundos. Solo necesita lo que viaja con el repositorio
(`models/`, `data/demo/`, `reports/resultados_*/`). Las dos pruebas marcadas
`datos_locales` (R7 y R13 en su versión pesada) se ejecutan únicamente si
existen los datos grandes en `data/`; si no, se omiten con su razón.

## Qué se verifica por código y qué requiere una persona

| Req. | Automatizada | Qué comprueba |
|---|---|---|
| R1 | ✅ | 11 clases en la evaluación final (benigno + 10), Heartbleed e Infiltration fuera del multiclase y presentes en el binario; una clase por flujo |
| R2 | ✅ | Falsas alarmas sobre los 414.468 benignos del test ≤ 0,2 % |
| R3 | ✅ | Importancia global disponible; SHAP explica 10 alertas de la demo con 8 pesos no nulos y clase coherente |
| R4 | ✅ | Recall > 0,4 en Heartbleed, slowloris e Infiltration al 1 % (semana y test); las camufladas quedan < 0,05 y la pantalla lo declara |
| R5 | ✅ | Macro-F1 final supera 0,082 por más de 0,5; reducción de carga > 90 % en la demo realista |
| R6 | ✅ | Macro-F1 en test ≥ 0,94, también sin el puerto |
| R7 | ✅ (+ pesada) | Semilla 42 declarada; dos clasificaciones idénticas; re-entrenar el detector reproduce los umbrales decimal a decimal |
| R8 | ✅ | Solo `evaluacion_final.py` evalúa el test (`preparar_demo.py` solo muestrea, autorizado por §6); escalado y remuestreo dentro del pipeline; prueba dentro de CV ± 3σ |
| R9 | ✅ parcial | 50.000 flujos en < 30 s **en local**; la medición definitiva es sobre el tablero desplegado |
| R10 | ⏸ manual | Abrir la URL pública desde otro equipo; reanudación < 1 min |
| R11 | ✅ | CSV por día presente (8 tramos × 3 umbrales); mediana ≈ 1 %, un tramo > 5 %; la pantalla lo expone y explica la deriva |
| R12 | ✅ | Los cuatro archivos: válido, columnas faltantes, vacío, valores inválidos (+ etiqueta, basura binaria) |
| R13 | ✅ (+ pesada) | Sin Inf/NaN tras depurar lo subido; el Parquet limpio tiene 2.498.078 filas y ningún valor no finito |
| R14 | ✅ | Cada flujo trae clase binaria, multiclase y confianza en [0, 1] |
| R15 | ✅ | El conteo de anómalos crece 0,5 % → 1 % → 2 % y los cortes salen del detector |
| R16 | ⏸ manual | Contar clics: resumen 1, métricas 2, explicación de una alerta 3, exportar filtrado 3 |
| R17 | ✅ | El CSV exportado refleja exactamente el filtro (tipo, confianza, anomalía); las métricas también se exportan |
| R18 | ✅ | Procesar un archivo no crea ningún archivo en disco; las 48 características son numéricas y sin IPs, IDs ni contenido |
| R19 | ⏸ no verificable | Integración SIEM: deseable; la exportación CSV es la vía de esta iteración |
| R20 | ⏸ manual | Persona ajena completa cargar → revisar → exportar sin ayuda |
| R21 | ✅ parcial + ⏸ | Las 6 pantallas abren con título y una descripción de lo que muestran, las que tienen tablas traen su guía «Cómo leer» y las métricas tienen su explicación en llano (se revisa sobre el código, sin exigir frases exactas); la revisión por una persona ajena es manual |
| R22 | ⏸ manual | Abrir el tablero desplegado en Chrome, Firefox y Edge |

Las manuales aparecen en la salida como `SKIPPED` con la razón completa, para
que el mismo reporte deje constancia de qué falta verificar con una persona o
con el despliegue.

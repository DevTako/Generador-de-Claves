# Generador y auditor de contraseñas

Herramienta de línea de comandos para generar contraseñas aleatorias y auditarlas:
calcula la entropía exacta del espacio de búsqueda, estima el tiempo de crackeo según
el algoritmo de hash y verifica si la contraseña aparece en filtraciones conocidas
**sin enviarla** (k-anonymity con Have I Been Pwned).

## Uso

```bash
python generador.py -l 16 -n 3 --excluir-ambiguos --algoritmo bcrypt --verificar
```

| Opción | Descripción |
|---|---|
| `-l`, `--longitud` | Longitud (8–128, por defecto 16) |
| `-n`, `--cantidad` | Cuántas contraseñas generar |
| `--sin-simbolos` | Omite símbolos |
| `--excluir-ambiguos` | Omite caracteres confusos (`l I 1 O 0 \|` …) |
| `--algoritmo` | Hash asumido: `md5`, `sha256`, `bcrypt`, `argon2` |
| `--verificar` | Consulta Have I Been Pwned (requiere internet) |

Pruebas: `pip install -r requirements-dev.txt && pytest -q`

## Decisiones de diseño

**`secrets` y no `random`.** El módulo `random` usa Mersenne Twister, un PRNG
predecible que no es apto para criptografía. `secrets` usa el generador seguro del
sistema operativo.

**Una de cada clase, luego mezcla.** Garantiza que cumpla políticas habituales
(minúscula, mayúscula, dígito, símbolo). El orden final se baraja con
`secrets.SystemRandom().shuffle` para que las posiciones no sean predecibles.

**Entropía exacta.** Forzar una de cada clase reduce el espacio respecto a `94^n`.
El tamaño real se calcula por inclusión-exclusión sobre las clases: se cuenta el total
y se restan las contraseñas a las que les falta alguna clase, corrigiendo los solapes.
La entropía es el log₂ de ese número.

**k-anonymity en HIBP.** Se calcula el SHA-1 localmente y solo se envían sus 5 primeros
caracteres. La API devuelve todos los sufijos que coinciden y la comparación se hace en
local. La contraseña nunca sale del equipo.

## Modelo de amenazas

**Protege contra:**
- Fuerza bruta offline sobre una base de hashes filtrada.
- Uso de contraseñas ya expuestas en filtraciones (con `--verificar`).

**No protege contra:**
- Phishing, ingeniería social, keyloggers o malware en el equipo.
- Reutilización de la contraseña entre servicios.
- Contraseñas mostradas en pantalla o guardadas en el historial de la terminal.

## Limitaciones

- La entropía solo es válida para contraseñas **generadas al azar**; no aplica a las que
  elige una persona.
- Las velocidades de `VELOCIDADES` son órdenes de magnitud aproximados para una GPU de
  gama alta y varían mucho con la configuración del hash (p. ej. coste de bcrypt).
- La estimación asume ataque de fuerza bruta pura, sin diccionarios ni reglas.
- La verificación con HIBP depende de conexión y de la disponibilidad del servicio.

## Posibles mejoras

- Modo passphrase (estilo Diceware).
- Empaquetado como paquete instalable con `pip`.
- Modularizar si el código crece (hoy es deliberadamente un solo archivo).

## Licencia

MIT

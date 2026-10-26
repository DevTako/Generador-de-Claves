"""Generador y auditor de contraseñas.

- Generación con `secrets` (CSPRNG).
- Entropía exacta del espacio de contraseñas (inclusión-exclusión).
- Estimación de tiempo de crackeo según el algoritmo de hash.
- Verificación en filtraciones con Have I Been Pwned (k-anonymity).
"""

import argparse
import hashlib
import math
import secrets
import string
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------- Constantes
LONGITUD_MIN = 8
LONGITUD_MAX = 128
AMBIGUOS = "lI1O0|`'\""

# Velocidades APROXIMADAS (hashes/s) de una GPU de gama alta, orden de magnitud.
# Referencia: benchmarks públicos de hashcat. Ajusta según tu escenario.
VELOCIDADES = {
    "md5": 1e11,
    "sha256": 2e10,
    "bcrypt": 1e4,    # coste moderado
    "argon2": 1e2,    # parámetros por defecto razonables
}


# --------------------------------------------------------------- Generación
def construir_clases(sin_simbolos: bool = False, excluir_ambiguos: bool = False) -> list[str]:
    clases = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if not sin_simbolos:
        clases.append(string.punctuation)
    if excluir_ambiguos:
        clases = ["".join(c for c in clase if c not in AMBIGUOS) for clase in clases]
    return clases


def generar_contrasena(longitud: int, clases: list[str] | None = None) -> str:
    """Genera una contraseña con al menos un carácter de cada clase."""
    clases = clases or construir_clases()
    if not LONGITUD_MIN <= longitud <= LONGITUD_MAX:
        raise ValueError(f"La longitud debe estar entre {LONGITUD_MIN} y {LONGITUD_MAX}.")

    todos = "".join(clases)
    caracteres = [secrets.choice(c) for c in clases]
    caracteres += [secrets.choice(todos) for _ in range(longitud - len(clases))]
    secrets.SystemRandom().shuffle(caracteres)
    return "".join(caracteres)


# ------------------------------------------------------- Entropía y crackeo
def calcular_entropia(longitud: int, clases: list[str] | None = None) -> float:
    """Entropía (bits) del conjunto de contraseñas de `longitud` caracteres
    con al menos un carácter de cada clase. Inclusión-exclusión sobre clases.
    Solo es válida para contraseñas generadas al azar."""
    clases = clases or construir_clases()
    total = sum(len(c) for c in clases)
    validas = 0
    for mask in range(1 << len(clases)):
        excluido = sum(len(c) for i, c in enumerate(clases) if mask & (1 << i))
        signo = -1 if mask.bit_count() % 2 else 1
        validas += signo * (total - excluido) ** longitud
    return math.log2(validas)


def estimar_tiempo_crackeo(entropia: float, velocidad: float = VELOCIDADES["md5"]) -> str:
    """Tiempo medio de fuerza bruta offline (se prueba la mitad del espacio)."""
    segundos = 2 ** (entropia - 1) / velocidad

    if segundos < 60:
        return "Instantáneo / pocos segundos"
    if segundos < 3600:
        return f"{segundos / 60:.1f} minutos"
    if segundos < 86_400:
        return f"{segundos / 3600:.1f} horas"
    if segundos < 31_536_000:
        return f"{segundos / 86_400:.1f} días"

    anios = segundos / 31_536_000
    if anios < 1_000:
        return f"{anios:.1f} años"
    if anios < 1_000_000:
        return f"{anios / 1_000:.1f} miles de años"
    if anios < 1_000_000_000:
        return f"{anios / 1_000_000:.1f} millones de años"
    return "Prácticamente inviable"


# ------------------------------------------------------------------- HIBP
def aparece_en_filtraciones(contrasena: str, timeout: int = 10) -> int:
    """Veces que aparece en filtraciones conocidas (0 = no aparece).
    Solo se envían los 5 primeros caracteres del SHA-1 (k-anonymity)."""
    sha1 = hashlib.sha1(contrasena.encode("utf-8")).hexdigest().upper()
    prefijo, sufijo = sha1[:5], sha1[5:]

    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefijo}",
        headers={"User-Agent": "generador-portafolio"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for linea in resp.read().decode().splitlines():
            hash_sufijo, _, cantidad = linea.partition(":")
            if hash_sufijo.strip() == sufijo:
                return int(cantidad)
    return 0


# -------------------------------------------------------------------- CLI
def parsear_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generador y auditor de contraseñas")
    p.add_argument("-l", "--longitud", type=int, default=16, help="longitud (default: 16)")
    p.add_argument("-n", "--cantidad", type=int, default=1, help="cuántas generar")
    p.add_argument("--sin-simbolos", action="store_true", help="omitir símbolos")
    p.add_argument("--excluir-ambiguos", action="store_true", help="omitir l, I, 1, O, 0, |...")
    p.add_argument("--algoritmo", choices=VELOCIDADES, default="md5",
                   help="hash asumido para estimar el crackeo (default: md5)")
    p.add_argument("--verificar", action="store_true",
                   help="consultar Have I Been Pwned (requiere internet)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parsear_args(argv)
    if args.cantidad < 1:
        print("Error: la cantidad debe ser al menos 1.", file=sys.stderr)
        return 1

    clases = construir_clases(args.sin_simbolos, args.excluir_ambiguos)
    try:
        entropia = calcular_entropia(args.longitud, clases)
        claves = [generar_contrasena(args.longitud, clases) for _ in range(args.cantidad)]
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    tiempo = estimar_tiempo_crackeo(entropia, VELOCIDADES[args.algoritmo])

    for clave in claves:
        print(f"Contraseña: {clave}")
        if args.verificar:
            try:
                n = aparece_en_filtraciones(clave)
                print(f"  Filtraciones: {'NO aparece' if n == 0 else f'APARECE {n} veces'}")
            except (urllib.error.URLError, TimeoutError) as e:
                print(f"  Filtraciones: no se pudo consultar ({e})")

    print(f"\nEntropía:          {entropia:.2f} bits")
    print(f"Crackeo ({args.algoritmo}): {tiempo}")
    if entropia < 80:
        print("Aviso: usa 14 o más caracteres para mayor seguridad.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

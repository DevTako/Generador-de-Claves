import io
import math
import string

import pytest

import generador as g


def test_longitud_y_clases():
    for _ in range(200):
        p = g.generar_contrasena(12)
        assert len(p) == 12
        assert any(c in string.ascii_lowercase for c in p)
        assert any(c in string.ascii_uppercase for c in p)
        assert any(c in string.digits for c in p)
        assert any(c in string.punctuation for c in p)


def test_sin_simbolos():
    clases = g.construir_clases(sin_simbolos=True)
    for _ in range(100):
        assert not any(c in string.punctuation for c in g.generar_contrasena(16, clases))


def test_excluir_ambiguos():
    clases = g.construir_clases(excluir_ambiguos=True)
    for _ in range(100):
        assert not any(c in g.AMBIGUOS for c in g.generar_contrasena(20, clases))


@pytest.mark.parametrize("longitud", [g.LONGITUD_MIN - 1, g.LONGITUD_MAX + 1])
def test_longitud_invalida(longitud):
    with pytest.raises(ValueError):
        g.generar_contrasena(longitud)


def test_entropia_exacta_caso_pequeno():
    # Longitud 4 con 4 clases: exactamente un carácter de cada clase, en 4! órdenes.
    esperado = math.log2(24 * 26 * 26 * 10 * 32)
    assert g.calcular_entropia(4) == pytest.approx(esperado)


def test_entropia_menor_o_igual_a_cota_simple():
    cota = 16 * math.log2(94)
    assert g.calcular_entropia(16) <= cota
    assert g.calcular_entropia(16) > cota - 1  # diferencia pequeña


def test_estimacion_tiempo():
    assert "Instantáneo" in g.estimar_tiempo_crackeo(10)
    assert "inviable" in g.estimar_tiempo_crackeo(200)
    # Más lento el hash => más tiempo (en la misma entropía)
    assert g.estimar_tiempo_crackeo(60, 1e2) != g.estimar_tiempo_crackeo(60, 1e11)


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_hibp_sin_red(monkeypatch):
    # SHA-1 de "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    cuerpo = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\r\nAAAAA0000000000000000000000000000AA:1\r\n"
    llamadas = []

    def falso_urlopen(req, timeout=10):
        llamadas.append(req.full_url)
        return _FakeResp(cuerpo.encode())

    monkeypatch.setattr(g.urllib.request, "urlopen", falso_urlopen)
    assert g.aparece_en_filtraciones("password") == 99
    assert llamadas[0].endswith("/range/5BAA6")  # solo se envía el prefijo


def test_hibp_no_encontrada(monkeypatch):
    monkeypatch.setattr(g.urllib.request, "urlopen",
                        lambda req, timeout=10: _FakeResp(b"AAAAA0000000000000000000000000000AA:1\r\n"))
    assert g.aparece_en_filtraciones("x-unica-!@#") == 0


def test_cli_ok(capsys):
    assert g.main(["-l", "16", "-n", "2"]) == 0
    salida = capsys.readouterr().out
    assert salida.count("Contraseña:") == 2
    assert "Entropía" in salida


def test_cli_longitud_invalida(capsys):
    assert g.main(["-l", "3"]) == 1
    assert "Error" in capsys.readouterr().err

import cves


class Resp:
    def __init__(self, code, js=None):
        self.status_code, self._js = code, js or {}

    def json(self):
        return self._js


def _cve(id_, score, sev):
    return {"cve": {"id": id_, "descriptions": [{"lang": "en", "value": id_}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]}}}


def _preparar(monkeypatch, tmp_path, respuesta):
    llamadas = []

    def falso(url, params=None, headers=None, timeout=0):
        llamadas.append(params["cpeName"])
        return respuesta

    monkeypatch.setattr(cves, "CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(cves, "_esperar", lambda k: None)
    monkeypatch.setattr(cves.requests, "get", falso)
    return llamadas


def test_ordena_por_gravedad_y_usa_cache(monkeypatch, tmp_path):
    resp = Resp(200, {"vulnerabilities": [_cve("BAJO", 4.1, "MEDIUM"), _cve("ALTO", 9.8, "CRITICAL")]})
    llamadas = _preparar(monkeypatch, tmp_path, resp)
    datos = cves.buscar_cves("cpe:2.3:a:jquery:jquery", "3.4.1")
    assert [c["id"] for c in datos["cves"]] == ["ALTO", "BAJO"]
    cves.buscar_cves("cpe:2.3:a:jquery:jquery", "3.4.1")
    assert len(llamadas) == 1  # la segunda salio de la cache
    assert llamadas[0] == "cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*"


def test_errores_de_nvd_se_reportan_sin_romper(monkeypatch, tmp_path):
    _preparar(monkeypatch, tmp_path, Resp(429))
    r = cves.enriquecer({"PHP": "8.0.0"}, {"PHP": {"cpe": "cpe:2.3:a:php:php"}})
    assert "limite" in r["PHP"]["nota"]


def test_sin_version_o_sin_cpe_no_consulta(monkeypatch, tmp_path):
    llamadas = _preparar(monkeypatch, tmp_path, Resp(200))
    reglas = {"A": {"cpe": "x"}, "B": {}}
    r = cves.enriquecer({"A": None, "B": "1.0"}, reglas)
    assert llamadas == []
    assert r["A"]["nota"] and r["B"]["nota"]

"""TechDetect - Fase 3: cruce de versiones detectadas con CVEs de la NVD.
Consulta la API publica NVD 2.0 (https://nvd.nist.gov). Resultado ORIENTATIVO:
la version que muestra un servidor puede estar parcheada (backports) o ser falsa.
Clave API opcional (mas velocidad): variable de entorno NVD_API_KEY."""
import json
import os
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path(__file__).with_name("cache_cves.json")
CACHE_TTL = 24 * 3600
_ultima_llamada = 0.0


class ErrorNVD(Exception):
    pass


def _leer_cache():
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _guardar_cache(cache):
    try:
        CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass  # la cache es opcional


def _cvss(metricas):
    for clave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metricas.get(clave):
            m = metricas[clave][0]
            datos = m.get("cvssData", {})
            sev = datos.get("baseSeverity") or m.get("baseSeverity") or "N/D"
            return float(datos.get("baseScore", 0.0)), sev
    return 0.0, "N/D"


def _esperar(api_key):
    """Respeta el limite de la NVD: 5 peticiones/30 s sin clave, 50/30 s con clave."""
    global _ultima_llamada
    pausa = 0.7 if api_key else 6.5
    falta = pausa - (time.time() - _ultima_llamada)
    if falta > 0:
        time.sleep(falta)
    _ultima_llamada = time.time()


def buscar_cves(cpe_base, version, api_key=None):
    """Devuelve {'total': n, 'cves': [ {id, score, severidad, resumen} ... ]} ordenado por gravedad."""
    clave = f"{cpe_base}:{version}"
    cache = _leer_cache()
    hit = cache.get(clave)
    if hit and time.time() - hit["t"] < CACHE_TTL:
        return hit["datos"]

    _esperar(api_key)
    cpe = f"{cpe_base}:{version}" + ":*" * 7
    cab = {"apiKey": api_key} if api_key else {}
    try:
        r = requests.get(NVD_URL, params={"cpeName": cpe, "resultsPerPage": 200},
                         headers=cab, timeout=30)
    except requests.exceptions.RequestException as e:
        raise ErrorNVD(f"sin conexion con NVD ({type(e).__name__})")
    if r.status_code == 404:
        raise ErrorNVD("version no reconocida en la base de NVD")
    if r.status_code in (403, 429):
        raise ErrorNVD("limite de peticiones de NVD alcanzado; espera 30 s o usa NVD_API_KEY")
    if r.status_code != 200:
        raise ErrorNVD(f"NVD respondio HTTP {r.status_code}")

    cves = []
    for item in r.json().get("vulnerabilities", []):
        c = item.get("cve", {})
        score, sev = _cvss(c.get("metrics", {}))
        resumen = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        cves.append({"id": c.get("id", "?"), "score": score, "severidad": sev, "resumen": resumen})
    cves.sort(key=lambda x: x["score"], reverse=True)
    datos = {"total": len(cves), "cves": cves}
    cache[clave] = {"t": time.time(), "datos": datos}
    _guardar_cache(cache)
    return datos


def enriquecer(encontradas, reglas, api_key=None, progreso=None):
    """Para cada tecnologia con version Y cpe, busca CVEs. Devuelve {tec: info}."""
    api_key = api_key or os.environ.get("NVD_API_KEY")
    salida = {}
    for tec, ver in sorted(encontradas.items()):
        info = {"version": ver, "total": None, "cves": [], "nota": ""}
        cpe = reglas.get(tec, {}).get("cpe")
        if not ver:
            info["nota"] = "version no detectada: no se puede cruzar con CVEs"
        elif not cpe:
            info["nota"] = "sin CPE en las reglas: no se consulta NVD"
        else:
            if progreso:
                progreso(f"Consultando NVD: {tec} {ver} ...")
            try:
                datos = buscar_cves(cpe, ver, api_key)
                info["total"], info["cves"] = datos["total"], datos["cves"]
            except ErrorNVD as e:
                info["nota"] = str(e)
        salida[tec] = info
    return salida


def formatear(resultado, max_cves=5):
    """Texto legible del resultado de enriquecer()."""
    lineas = []
    for tec, i in resultado.items():
        lineas.append(f"{tec}" + (f" {i['version']}" if i["version"] else ""))
        if i["nota"]:
            lineas.append(f"    ({i['nota']})")
        elif i["total"] == 0:
            lineas.append("    Sin CVEs registrados para esta version.")
        elif i["total"]:
            lineas.append(f"    {i['total']} CVEs. Los {min(max_cves, i['total'])} mas graves:")
            for c in i["cves"][:max_cves]:
                lineas.append(f"    - {c['id']}  {c['score']} {c['severidad']}  {c['resumen'][:80]}...")
    return "\n".join(lineas)

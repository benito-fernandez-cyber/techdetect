"""TechDetect - Fase 1: motor de deteccion pasiva de tecnologias web.
Solo lee lo que el servidor ya muestra publicamente. Usar en sitios propios o con permiso."""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

RULES_PATH = Path(__file__).with_name("rules.json")
USER_AGENT = "TechDetect/0.1 (analisis pasivo educativo)"


def cargar_reglas(ruta=RULES_PATH):
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def _version(match):
    """Devuelve el primer grupo capturado no vacio (la version), si existe."""
    for g in match.groups():
        if g and re.fullmatch(r"[\d.]+", g):
            return g
    return None


def _buscar(patron, texto):
    m = re.search(patron, texto or "", re.I)
    return (True, _version(m)) if m else (False, None)


def analizar(html, headers, cookies, reglas):
    """Compara respuesta contra reglas. Devuelve {tecnologia: version|None}."""
    headers = {k.lower(): v for k, v in headers.items()}
    scripts = " ".join(re.findall(r'<(?:script|link)[^>]+(?:src|href)=["\']([^"\']+)', html, re.I))
    metas = dict(
        (n.lower(), c)
        for n, c in re.findall(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)', html, re.I)
    )
    encontradas = {}

    def registrar(tec, version):
        if tec not in encontradas or (version and not encontradas[tec]):
            encontradas[tec] = version

    for tec, r in reglas.items():
        for patron in r.get("html", []):
            ok, v = _buscar(patron, html)
            if ok:
                registrar(tec, v)
        for patron in r.get("scripts", []):
            ok, v = _buscar(patron, scripts)
            if ok:
                registrar(tec, v)
        for nombre, patron in r.get("meta", {}).items():
            ok, v = _buscar(patron, metas.get(nombre.lower(), ""))
            if ok:
                registrar(tec, v)
        for cab, patron in r.get("headers", {}).items():
            ok, v = _buscar(patron, headers.get(cab.lower(), ""))
            if ok:
                registrar(tec, v)
        for nombre in r.get("cookies", []):
            if nombre in cookies:
                registrar(tec, None)
    return encontradas


def detectar(url, reglas=None):
    if not urlparse(url).scheme:
        url = "https://" + url
    reglas = reglas or cargar_reglas()
    r = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
    return analizar(r.text, r.headers, r.cookies.get_dict(), reglas)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Deteccion pasiva de tecnologias web")
    ap.add_argument("url")
    ap.add_argument("--cves", action="store_true", help="cruzar versiones con CVEs de la NVD")
    args = ap.parse_args()
    res = detectar(args.url)
    if args.cves:
        from cves import enriquecer, formatear
        print(formatear(enriquecer(res, cargar_reglas(), progreso=print)))
    else:
        for tec, ver in sorted(res.items()):
            print(f"- {tec}" + (f" {ver}" if ver else ""))

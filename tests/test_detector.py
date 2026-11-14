from detector import analizar, cargar_reglas

HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<script src="/wp-content/themes/x/jquery-3.6.0.min.js"></script>
<link href="/css/bootstrap-5.3.0.min.css" rel="stylesheet">
</head><body>Hola</body></html>"""


def test_detecta_tecnologias_y_versiones_en_html():
    res = analizar(HTML, {}, {}, cargar_reglas())
    assert res["WordPress"] == "6.4.2"
    assert res["jQuery"] == "3.6.0"
    assert res["Bootstrap"] == "5.3.0"


def test_detecta_por_cabeceras_y_cookies():
    headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.1"}
    res = analizar("<html></html>", headers, {"PHPSESSID": "abc"}, cargar_reglas())
    assert res["Nginx"] == "1.24.0"
    assert res["PHP"] == "8.2.1"


def test_las_cabeceras_no_distinguen_mayusculas():
    res = analizar("", {"server": "Apache/2.4.58"}, {}, cargar_reglas())
    assert res["Apache"] == "2.4.58"


def test_pagina_vacia_no_da_falsos_positivos():
    assert analizar("<html><body>nada</body></html>", {}, {}, cargar_reglas()) == {}


def test_todas_las_reglas_son_regex_validas():
    import re
    for tec, r in cargar_reglas().items():
        for clave in ("html", "scripts"):
            for p in r.get(clave, []):
                re.compile(p)
        for p in list(r.get("meta", {}).values()) + list(r.get("headers", {}).values()):
            re.compile(p)

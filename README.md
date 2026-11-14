# TechDetect

Detector **pasivo** de tecnologías web, inspirado en Wappalyzer, escrito en Python. Identifica CMS, frameworks, servidores y librerías a partir de lo que un sitio ya muestra públicamente (cabeceras HTTP, HTML, scripts, metaetiquetas y cookies) y, opcionalmente, **cruza las versiones detectadas con los CVEs de la NVD**.

Pensado como herramienta de **reconocimiento y revisión de superficie de exposición** para Blue Team / SOC: saber qué corre un activo propio y si esa versión tiene vulnerabilidades conocidas.

<img width="701" height="591" alt="docs-captura1" src="https://github.com/user-attachments/assets/493ad17e-4f89-464c-8d19-3ec5e26edd15" />


## Características

- Motor de reglas **separado del código** (`rules.json`): añadir una tecnología no requiere tocar Python.
- 29 tecnologías incluidas: CMS (WordPress, Drupal, Joomla), e-commerce, frameworks JS, servidores web, analítica...
- **Extracción de versiones** mediante grupos de captura en las expresiones regulares.
- **Cruce con CVEs** (API NVD 2.0): resultados ordenados por gravedad CVSS, con caché local de 24 h y respeto del límite de peticiones.
- Interfaz gráfica (CustomTkinter) y línea de comandos.
- Peticiones en hilo aparte: la ventana no se congela.
- Tests automáticos (`tests/`).

## Instalación

```bash
git clone https://github.com/benito-fernandez-cyber/techdetect.git
cd techdetect
pip install -r requirements.txt
```

## Uso

**Línea de comandos**

```bash
python detector.py https://tu-sitio.com
python detector.py https://tu-sitio.com --cves
```

Ejemplo de salida (sin `--cves`):

```
- Bootstrap 5.3.0
- WordPress 6.4.2
- jQuery 3.6.0
```

**Interfaz gráfica**

```bash
python gui.py
```

**Clave de la NVD (opcional).** Sin clave, la NVD permite 5 peticiones cada 30 s y la herramienta espera entre consultas. Con una clave gratuita va más rápido:

```bash
export NVD_API_KEY="tu-clave"        # Linux / macOS
setx NVD_API_KEY "tu-clave"          # Windows (reabre la terminal)
```

## Cómo funciona

1. Descarga la página con `requests` (una sola petición GET).
2. Extrae cabeceras, HTML, rutas de scripts/CSS, metaetiquetas y cookies.
3. Compara cada elemento con las expresiones regulares de `rules.json`.
4. Si hay versión y la regla tiene un `cpe`, consulta la NVD con el identificador CPE 2.3 y ordena los CVEs por puntuación CVSS.

**Formato de una regla**

```json
"jQuery": {
  "scripts": ["jquery[-.]?([\\d.]+)?(\\.min)?\\.js"],
  "cpe": "cpe:2.3:a:jquery:jquery"
}
```

Claves admitidas: `html`, `scripts`, `meta`, `headers`, `cookies` y `cpe`. El primer grupo de captura numérico se interpreta como versión.

## Limitaciones (léelas antes de fiarte de un resultado)

- Los resultados de CVEs son **orientativos**. Un servidor puede mostrar una versión ya parcheada (en distribuciones como Debian o Ubuntu se hace *backporting* de parches sin cambiar el número de versión) u ocultarla o falsearla.
- Solo analiza la **página que se le indica**, sin renderizar JavaScript: no ve lo que se carga dinámicamente.
- Solo 10 de las 29 tecnologías tienen CPE configurado para consultar la NVD.
- Detección basada en huellas conocidas: una tecnología sin regla no aparece.

## Uso responsable

Es un análisis pasivo (una petición normal), pero **úsalo solo contra sitios propios o con autorización**. No lo lances de forma masiva contra webs de terceros.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Hoja de ruta

- [ ] Más reglas y CPE para más tecnologías
- [ ] Exportar resultados a JSON/CSV
- [ ] Análisis de varias URLs desde un fichero (con pausa entre peticiones)
- [ ] Detección de cabeceras de seguridad ausentes (CSP, HSTS...)

## Autor

**Benito Fernández** — Analista de Ciberseguridad / SOC Junior
[LinkedIn](https://www.linkedin.com/in/benito-fernandez-ciberseguridad) · [Portfolio](https://cyber-profile.com)

## Licencia

MIT. Consulta el archivo `LICENSE`.

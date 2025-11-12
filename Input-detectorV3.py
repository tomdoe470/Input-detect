#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Input-detectV2.py - Versión corregida y comentada
Detector de inputs y reconocimiento web orientado a preparar pruebas
WSTG-IMPV (Input Validation) - v2.0 (refactor + mejoras)
Autor: (adaptado / corregido)
Fecha: (generado)
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import random
import time
import json
import re
import logging
from datetime import datetime
from colorama import init, Fore, Style
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Inicializar colorama para salida coloreada
init(autoreset=True)

# -----------------------
# Configuración y constantes
# -----------------------

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 13; Mobile; rv:107.0) Gecko/107.0 Firefox/107.0',
]

BASE_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# Extensiones que no interesan para el crawler (binarios, multimedia, fuentes, etc.)
EXCLUDED_EXTENSIONS = ['.pdf', '.zip', '.exe', '.jpg', '.jpeg', '.png', '.gif',
                       '.mp4', '.mp3', '.avi', '.mov', '.css', '.js', '.ico',
                       '.svg', '.woff', '.woff2', '.ttf', '.eot']

# Límites por defecto
MAX_URLS_DEFAULT = 1000
MAX_DEPTH_DEFAULT = 2

# Headers de seguridad que verificamos
SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy'
]

# Indicadores simples de tecnologías por patrones de contenido
TECH_INDICATORS = {
    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
    'Django': ['csrfmiddlewaretoken', '__admin'],
    'Laravel': ['laravel_session', '_token'],
    'React': ['react', 'reactdom'],
    'Angular': ['ng-', 'angular'],
    'Vue.js': ['vue', 'v-if', 'v-for'],
    'PHP': ['.php', 'PHPSESSID'],
    'ASP.NET': ['__VIEWSTATE', 'aspnet'],
    'Joomla': ['joomla', 'com_content'],
    'Drupal': ['drupal', 'sites/all']
}

# -----------------------
# Setup global HTTP session (retries, keep-alive)
# -----------------------

# Usamos una sesión global para reusar conexiones y aplicar política de reintentos
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.6, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retries)
session.mount('http://', adapter)
session.mount('https://', adapter)

# -----------------------
# Logging
# -----------------------
def setup_logging(quiet_mode=False, log_file=None):
    """Configura logging de forma segura. quiet_mode reduce nivel a WARNING."""
    if log_file:
        handlers = [logging.FileHandler(log_file)]
        if not quiet_mode:
            handlers.append(logging.StreamHandler())
        else:
            handlers.append(logging.NullHandler())
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=handlers)
    else:
        level = logging.WARNING if quiet_mode else logging.INFO
        logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

# -----------------------
# Utilidades comunes
# -----------------------

def should_skip_url(url):
    """
    Indica si una URL corresponde a una extensión que queremos evitar.
    Normaliza path y verifica sufijos.
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS)
    except Exception:
        return True

def is_allowed_by_robots(url, robots_info):
    """
    Reglas simples para respetar robots.txt: si robots_info['exists'] y una ruta
    coincide por prefijo con un disallow se considera no permitida.
    (No es un parser completo de robots, es una implementación básica.)
    """
    if not robots_info or not robots_info.get('exists'):
        return True
    parsed = urlparse(url)
    path = parsed.path or '/'
    disallowed = robots_info.get('disallowed', [])
    for dis in disallowed:
        # Normalizar
        if not dis:
            continue
        # Si el disallow es '/' o path empieza por disallow -> no permitido
        if dis == '/' or path.startswith(dis):
            return False
    return True

def detect_waf(response):
    """
    Detecta WAFs por indicadores en nombres y valores de headers.
    (Mejor que mirar solo nombres.)
    """
    waf_headers = {
        'cloudflare': ['cf-ray', 'cloudflare'],
        'akamai': ['akamai'],
        'incapsula': ['incap_ses', 'visid_incap'],
        'sucuri': ['sucuri', 'x-sucuri'],
        'aws-waf': ['x-amzn-requestid', 'x-amz-cf-id']
    }

    detected = set()
    # Normalizar nombres y valores
    headers_lower = {k.lower(): (v.lower() if isinstance(v, str) else '') for k, v in response.headers.items()}
    header_values_concat = " ".join(headers_lower.values())
    header_names_concat = " ".join(headers_lower.keys())

    for waf_name, indicators in waf_headers.items():
        for indicator in indicators:
            if indicator in header_values_concat or indicator in header_names_concat:
                detected.add(waf_name)
                break
    return list(detected)

def check_security_headers(response):
    """
    Revisa si los headers de seguridad esperados están presentes (case-insensitive).
    Retorna dict con 'missing' y 'present' (valores).
    """
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    missing = []
    present = {}
    for header in SECURITY_HEADERS:
        if header.lower() in headers_lower:
            present[header] = headers_lower[header.lower()]
        else:
            missing.append(header)
    return {'missing': missing, 'present': present}

def detect_technologies(html_content, response_headers):
    """
    Detecta tecnologías por patrones en HTML y valores de headers (servidor / x-powered-by).
    """
    detected = set()
    content_lower = (html_content or '').lower()
    for tech, indicators in TECH_INDICATORS.items():
        for indicator in indicators:
            if indicator.lower() in content_lower:
                detected.add(tech)
                break

    server = response_headers.get('Server', '') or response_headers.get('server', '')
    server = server.lower() if isinstance(server, str) else ''
    if 'nginx' in server:
        detected.add('Nginx')
    elif 'apache' in server:
        detected.add('Apache')
    elif 'iis' in server:
        detected.add('IIS')

    x_powered = response_headers.get('X-Powered-By', '') or response_headers.get('x-powered-by', '')
    x_powered = x_powered.lower() if isinstance(x_powered, str) else ''
    if 'php' in x_powered:
        detected.add('PHP')
    elif 'asp.net' in x_powered or 'aspnet' in x_powered:
        detected.add('ASP.NET')

    return list(detected)

def find_js_params(html_content):
    """
    Busca parámetros básicos que puedan estar embebidos en HTML/JS.
    Esta función es heurística y puede generar falsos positivos.
    """
    if not html_content:
        return []
    patterns = [
        r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',     # parámetros en URLs
        r'\.get\(\s*["\']([^"\']+)["\']',      # .get('url') patrones
        r'params?\[\s*["\']([^"\']+)["\']',    # params['x']
        r'data\[\s*["\']([^"\']+)["\']',       # data['x']
    ]
    found = set()
    for pat in patterns:
        for m in re.findall(pat, html_content):
            found.add(m)
    return list(found)

def check_robots_txt(base_url):
    """
    Descarga robots.txt y extrae rutas Disallow (implementación simple).
    """
    robots_url = urljoin(base_url, '/robots.txt')
    try:
        resp = session.get(robots_url, headers=BASE_HEADERS, timeout=6, verify=True)
        if resp.status_code == 200:
            disallowed = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.lower().startswith('disallow:'):
                    val = line.split(':', 1)[1].strip()
                    # Normalizar: asegurarse que empiece por '/'
                    if val and not val.startswith('/'):
                        val = '/' + val
                    disallowed.append(val)
            return {'exists': True, 'disallowed': disallowed}
    except Exception:
        pass
    return {'exists': False, 'disallowed': []}

# -----------------------
# Extracción de elementos HTML y JS
# -----------------------

def extract_internal_links(base_url, html_content):
    """
    Extrae enlaces internos (misma netloc) normalizados sin fragmentos.
    """
    links = set()
    if not html_content:
        return links
    soup = BeautifulSoup(html_content, 'html.parser')
    base_netloc = urlparse(base_url).netloc
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if not href:
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ('http', 'https'):
            continue
        if parsed.netloc != base_netloc:
            continue
        if should_skip_url(full):
            continue
        normalized = parsed.scheme + '://' + parsed.netloc + parsed.path
        if parsed.query:
            normalized += '?' + parsed.query
        links.add(normalized)
    return links

def identify_get_parameters(url):
    """
    Extrae parámetros GET (parse_qs devuelve listas de valores).
    """
    parsed = urlparse(url)
    if not parsed.query:
        return {}
    return parse_qs(parsed.query)

def extract_enhanced_form_inputs(base_url, html_content):
    """
    Extrae formularios con metadatos útiles: action completo, method, enctype,
    campos (name, type, value, hidden, required, pattern, minlength, maxlength, accept).
    """
    forms = []
    if not html_content:
        return forms
    soup = BeautifulSoup(html_content, 'html.parser')
    for form in soup.find_all('form'):
        action = form.get('action', '')
        full_action = urljoin(base_url, action)
        method = form.get('method', 'GET').upper()
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        form_fields = []
        # Considerar input, textarea, select, button
        for tag in form.find_all(['input', 'textarea', 'select', 'button']):
            name = tag.get('name')
            if not name:
                continue
            t = tag.get('type', 'text')
            field = {
                'name': name,
                'type': t,
                'value': tag.get('value', ''),
                'hidden': (t == 'hidden'),
                'required': tag.has_attr('required'),
                'pattern': tag.get('pattern', ''),
                'minlength': tag.get('minlength', ''),
                'maxlength': tag.get('maxlength', ''),
                'accept': tag.get('accept', '')
            }
            form_fields.append(field)
        if form_fields:
            forms.append({
                'action': full_action,
                'method': method,
                'enctype': enctype,
                'fields': form_fields,
                'has_file_upload': any(f['type'] == 'file' for f in form_fields)
            })
    return forms

def extract_cookies(response):
    """
    Extrae cookies desde la response. Extrae algunos flags si están presentes.
    Nota: Requests usa RequestsCookieJar; iterar sobre response.cookies devuelve
    objetos compatibl es con attributes: name, value, domain, path, secure, rest.
    """
    cookies = []
    try:
        for cookie in response.cookies:
            rest = getattr(cookie, 'rest', {}) or {}
            httponly = False
            # 'HttpOnly' puede aparecer en rest como clave
            for k in rest.keys():
                if k.lower() == 'httponly':
                    httponly = True
                    break
            cookie_data = {
                'name': getattr(cookie, 'name', ''),
                'value': getattr(cookie, 'value', ''),
                'domain': getattr(cookie, 'domain', ''),
                'path': getattr(cookie, 'path', ''),
                'secure': bool(getattr(cookie, 'secure', False)),
                'httponly': httponly
            }
            cookies.append(cookie_data)
    except Exception:
        pass
    return cookies

def extract_api_endpoints(html_content):
    """
    Heurística para extraer endpoints API a partir de código inline JS / HTML.
    Retorna rutas (relativas o absolutas) detectadas.
    """
    if not html_content:
        return []
    api_patterns = [
        r'fetch\(\s*["\']([^"\']+)["\']',                     # fetch('url')
        r'axios\.[a-zA-Z]+\(\s*["\']([^"\']+)["\']',          # axios.get('url')
        r'\.ajax\(\s*{[^}]*url:\s*["\']([^"\']+)["\']',       # $.ajax({url: '...'})
        r'XMLHttpRequest.*open\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',  # XHR open
        r'["\'](/api/[a-zA-Z0-9/_\-\{\}]+)["\']',              # '/api/endpoint'
        r'["\'](/v\d+/[a-zA-Z0-9/_\-\{\}]+)["\']'              # '/v1/...'
    ]
    endpoints = set()
    for pat in api_patterns:
        for m in re.findall(pat, html_content, re.IGNORECASE | re.DOTALL):
            endpoints.add(m)
    return list(endpoints)

def extract_custom_headers(html_content):
    """
    Busca referencias a nombres de headers personalizados dentro de JS para detectar
    posibles headers que el frontend añade (p.ej. 'X-My-App', 'Authorization').
    """
    if not html_content:
        return []
    patterns = [
        r'headers\s*:\s*{([^}]+)}',                 # headers: { 'X-...': ... }
        r'setRequestHeader\(\s*["\']([^"\']+)["\']',# setRequestHeader('Header-Name', ...)
        r'["\']Authorization["\']\s*:\s*["\']([^"\']+)["\']' # Authorization: 'Bearer ...' (captura clave)
    ]
    headers = set()
    for pat in patterns:
        for m in re.findall(pat, html_content, re.IGNORECASE | re.DOTALL):
            # Si el match es un bloque, extraer nombres entre comillas
            if '{' in m or ':' in m:
                found = re.findall(r'["\']([A-Za-z0-9\-\_]+)["\']\s*:', m)
                for h in found:
                    headers.add(h)
            else:
                headers.add(m)
    return list(headers)

def detect_json_payloads(html_content):
    """
    Heurística: busca snippets que parecen JSON o JSON.stringfy en JS in-line.
    No garantiza ser JSON válido.
    """
    if not html_content:
        return []
    patterns = [
        r'JSON\.stringify\(\s*({[^}]+})\s*\)',  # JSON.stringify({...})
        r'body\s*:\s*JSON\.stringify\(\s*([^\)]+)\)',  # body: JSON.stringify(obj)
        r'data\s*:\s*({[^}]+})'  # data: {...}
    ]
    results = []
    for pat in patterns:
        for m in re.findall(pat, html_content, re.DOTALL | re.IGNORECASE):
            results.append(m.strip())
    return results

def detect_websockets(html_content):
    """Detecta creación de WebSocket en JS."""
    if not html_content:
        return []
    pat = r'new\s+WebSocket\(\s*["\']([^"\']+)["\']'
    return re.findall(pat, html_content)

def detect_localstorage_usage(html_content):
    """Detecta claves usadas en localStorage/sessionStorage."""
    if not html_content:
        return []
    patterns = [
        r'localStorage\.getItem\(\s*["\']([^"\']+)["\']\s*\)',
        r'sessionStorage\.getItem\(\s*["\']([^"\']+)["\']\s*\)',
        r'localStorage\[\s*["\']([^"\']+)["\']\s*\]'
    ]
    keys = set()
    for pat in patterns:
        for m in re.findall(pat, html_content):
            keys.add(m)
    return list(keys)

# -----------------------
# Obtención de páginas con manejo de errores
# -----------------------

def get_page_content(url, verify_ssl=True, delay=0, quiet=False, max_redirects=5):
    """
    Obtiene una URL usando la sesión global. Maneja SSL, timeouts y retries (por session).
    Parámetros:
      - url: URL objetivo
      - verify_ssl: bool para verify param de requests
      - delay: segundos de espera antes de request
      - quiet: si True reduce prints interactivos
    Retorna: response o None en fallo.
    """
    try:
        if delay and delay > 0:
            time.sleep(delay)
        headers = BASE_HEADERS.copy()
        headers['User-Agent'] = random.choice(USER_AGENTS)
        if not quiet:
            print(f"{Fore.CYAN}[*] Obteniendo: {url}{Style.RESET_ALL}")
        logging.info(f"Requesting {url}")
        resp = session.get(url, headers=headers, timeout=12, verify=verify_ssl, allow_redirects=True)
        resp.raise_for_status()
        return resp
    except requests.exceptions.SSLError as e:
        logging.warning(f"SSL error for {url}: {e}")
        if not quiet:
            print(f"{Fore.YELLOW}[!] SSL error en {url}: {e} - usa --no-verify si es intencional{Style.RESET_ALL}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for {url}: {e}")
        if not quiet:
            print(f"{Fore.RED}[-] Error al obtener {url}: {e}{Style.RESET_ALL}")
        return None

# -----------------------
# Crawler mejorado (implementación principal)
# -----------------------

def advanced_crawler_enhanced(start_url, max_depth=2, max_urls=1000, verify_ssl=True, delay=0, check_robots=True, quiet=False):
    """
    Crawler principal mejorado orientado a WSTG-IMPV:
      - respeta robots.txt (opcional)
      - detecta inputs GET, forms, parámetros en JS
      - detecta cookies, endpoints API, headers personalizados, websockets, localStorage, JSON payloads
      - devuelve un dict con visited_urls, discovered_inputs y security_info
    """
    # Validación básica de URL
    if not start_url.startswith(('http://', 'https://')):
        if not quiet:
            print(f"{Fore.RED}[-] La URL debe comenzar con http:// o https://{Style.RESET_ALL}")
        return None

    visited_urls = set()
    urls_to_visit = [(start_url, 0)]
    discovered_inputs = []
    security_info = {
        'waf_detected': set(),
        'security_headers': {},
        'technologies': set(),
        'robots_txt': {},
        'js_parameters': set(),
        'cookies': [],            # lista de dicts
        'api_endpoints': set(),
        'custom_headers': set(),
        'websockets': set(),
        'storage_keys': set(),
        'json_payloads': []
    }

    # Obtener robots.txt si corresponde
    if check_robots:
        if not quiet:
            print(f"{Fore.CYAN}[*] Verificando robots.txt...{Style.RESET_ALL}")
        security_info['robots_txt'] = check_robots_txt(start_url)
        if security_info['robots_txt'].get('exists'):
            logging.info(f"robots.txt encontrado con {len(security_info['robots_txt'].get('disallowed', []))} rutas bloqueadas")

    if not quiet:
        print(f"{Fore.GREEN}[+] Iniciando rastreo: {start_url}")
        print(f"[+] Profundidad máxima: {max_depth}")
        print(f"[+] Límite de URLs: {max_urls}")
        print(f"[+] Delay entre peticiones: {delay}s")
        print(f"[+] Verificación SSL: {'Activada' if verify_ssl else 'Desactivada'}{Style.RESET_ALL}\n")

    first_request = True

    while urls_to_visit:
        # limite de urls
        if len(visited_urls) >= max_urls:
            if not quiet:
                print(f"{Fore.YELLOW}[!] Límite de URLs alcanzado ({max_urls}){Style.RESET_ALL}")
            logging.warning(f"Max URLs reached: {max_urls}")
            break

        current_url, current_depth = urls_to_visit.pop(0)

        # skip si ya visitada o profundidad excedida
        if current_url in visited_urls or current_depth > max_depth:
            continue

        # respetar robots
        if check_robots and not is_allowed_by_robots(current_url, security_info.get('robots_txt', {})):
            logging.info(f"URL bloqueada por robots.txt: {current_url}")
            if not quiet:
                print(f"{Fore.YELLOW}[!] URL bloqueada por robots.txt, saltando: {current_url}{Style.RESET_ALL}")
            visited_urls.add(current_url)
            continue

        if not quiet:
            print(f"{Fore.BLUE}[+] Visitando: {current_url} (Profundidad: {current_depth}){Style.RESET_ALL}")

        visited_urls.add(current_url)

        # Identificar parámetros GET directamente desde la URL
        get_params = identify_get_parameters(current_url)
        if get_params:
            discovered_inputs.append({
                'url': current_url,
                'type': 'GET_URL_PARAMS',
                'parameters': get_params
            })

        # Obtener contenido (permitir fetch en nivel igual al max_depth también)
        # Nota: aún añadimos enlaces con current_depth + 1, para no exceder la profundidad
        if current_depth <= max_depth:
            response = get_page_content(current_url, verify_ssl=verify_ssl, delay=(delay if not first_request else 0), quiet=quiet)
            first_request = False

            if response:
                html_content = response.text or ''
                # cookies
                cookies = extract_cookies(response)
                security_info['cookies'].extend(cookies)

                # api endpoints detectados en HTML/JS inline
                api_ep = extract_api_endpoints(html_content)
                for e in api_ep:
                    security_info['api_endpoints'].add(e)

                # custom headers detectados en JS
                custom_h = extract_custom_headers(html_content)
                for h in custom_h:
                    security_info['custom_headers'].add(h)

                # websockets
                ws = detect_websockets(html_content)
                for w in ws:
                    security_info['websockets'].add(w)

                # localStorage/sessionStorage keys
                skeys = detect_localstorage_usage(html_content)
                for k in skeys:
                    security_info['storage_keys'].add(k)

                # json payloads heurísticos
                jps = detect_json_payloads(html_content)
                security_info['json_payloads'].extend(jps)

                # WAF detection (primera página preferentemente)
                waf = detect_waf(response)
                if waf:
                    for w in waf:
                        security_info['waf_detected'].add(w)
                    if not quiet:
                        print(f"{Fore.YELLOW}[!] WAF Detectado: {', '.join(waf)}{Style.RESET_ALL}")

                # security headers y tecnologias (tomadas desde la primera página o start_url)
                if current_url == start_url:
                    security_info['security_headers'] = check_security_headers(response)
                    techs = detect_technologies(html_content, dict(response.headers))
                    for t in techs:
                        security_info['technologies'].add(t)
                    if not quiet and techs:
                        print(f"{Fore.CYAN}[*] Tecnologías detectadas: {', '.join(techs)}{Style.RESET_ALL}")

                # parámetros en JS heurísticos
                js_params = find_js_params(html_content)
                for p in js_params:
                    security_info['js_parameters'].add(p)

                # Extraer enlaces internos y encolar
                new_links = extract_internal_links(current_url, html_content)
                for link in new_links:
                    if link not in visited_urls:
                        # no encolamos sin más: respetar max_urls
                        if len(visited_urls) + len(urls_to_visit) < max_urls:
                            urls_to_visit.append((link, current_depth + 1))

                # Extraer formularios con metadatos enriquecidos
                forms = extract_enhanced_form_inputs(current_url, html_content)
                for form in forms:
                    input_type = f"FORM_{form['method']}"
                    discovered_inputs.append({
                        'url': current_url,
                        'form_action': form['action'],
                        'type': input_type,
                        'fields': form['fields']
                    })

    # Normalizar sets a listas para salida y eliminar duplicados
    security_info['api_endpoints'] = sorted(list(security_info['api_endpoints']))
    security_info['custom_headers'] = sorted(list(security_info['custom_headers']))
    security_info['websockets'] = sorted(list(security_info['websockets']))
    security_info['storage_keys'] = sorted(list(security_info['storage_keys']))
    security_info['js_parameters'] = sorted(list(security_info['js_parameters']))
    security_info['technologies'] = sorted(list(security_info['technologies']))
    security_info['waf_detected'] = sorted(list(security_info['waf_detected']))

    # Deduplicar discovered_inputs (simplemente por representación JSON)
    seen = set()
    dedup_inputs = []
    for inp in discovered_inputs:
        key = json.dumps(inp, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            dedup_inputs.append(inp)

    return {
        'visited_urls': sorted(list(visited_urls)),
        'discovered_inputs': dedup_inputs,
        'security_info': security_info,
        'scan_date': datetime.now().isoformat()
    }

# -----------------------
# Reporte y exportación
# -----------------------

def print_report_enhanced(results, quiet=False):
    """
    Imprime en consola el reporte mejorado con nuevas secciones:
      - cookies, api endpoints, websockets, localStorage keys, json payloads
    Recibe results tal como devuelve advanced_crawler_enhanced.
    """
    if not results:
        if not quiet:
            print(f"{Fore.RED}[-] No hay resultados para mostrar.{Style.RESET_ALL}")
        return

    security_info = results.get('security_info', {})
    visited_urls = results.get('visited_urls', [])
    discovered_inputs = results.get('discovered_inputs', [])

    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{'REPORTE DE RASTREO':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}📊 Estadísticas:{Style.RESET_ALL}")
    print(f"  • URLs visitadas: {len(visited_urls)}")
    print(f"  • Inputs descubiertos: {len(discovered_inputs)}")
    print(f"  • Fecha del escaneo: {results.get('scan_date')}")

    # Información de seguridad
    print(f"\n{Fore.CYAN}🛡️  Información de Seguridad:{Style.RESET_ALL}")
    wafs = security_info.get('waf_detected', [])
    if wafs:
        print(f"  • WAF Detectado: {Fore.YELLOW}{', '.join(wafs)}{Style.RESET_ALL}")
    else:
        print(f"  • WAF Detectado: {Fore.GREEN}No detectado{Style.RESET_ALL}")

    techs = security_info.get('technologies', [])
    if techs:
        print(f"  • Tecnologías: {', '.join(techs)}")

    robots = security_info.get('robots_txt', {})
    if robots.get('exists'):
        print(f"  • robots.txt: {Fore.GREEN}Presente{Style.RESET_ALL} ({len(robots.get('disallowed', []))} rutas bloqueadas)")
    else:
        print(f"  • robots.txt: {Fore.YELLOW}No encontrado{Style.RESET_ALL}")

    # Headers de seguridad
    missing_headers = security_info.get('security_headers', {}).get('missing', [])
    if missing_headers:
        print(f"  • Headers de seguridad faltantes ({len(missing_headers)}):")
        for header in missing_headers:
            print(f"    - {Fore.RED}{header}{Style.RESET_ALL}")
    else:
        print(f"  • Headers de seguridad: {Fore.GREEN}Todos presentes o no aplicables{Style.RESET_ALL}")

    # Nuevas secciones
    print(f"\n{Fore.CYAN}🍪 Cookies Detectadas:{Style.RESET_ALL}")
    cookies = security_info.get('cookies', [])
    if cookies:
        for cookie in cookies[:10]:
            secure_flag = f"{Fore.GREEN}Secure{Style.RESET_ALL}" if cookie.get('secure') else f"{Fore.RED}No Secure{Style.RESET_ALL}"
            httponly_flag = f"{Fore.GREEN}HttpOnly{Style.RESET_ALL}" if cookie.get('httponly') else f"{Fore.RED}No HttpOnly{Style.RESET_ALL}"
            print(f"  • {cookie.get('name')} (dom:{cookie.get('domain')}) — {secure_flag}, {httponly_flag}")

    print(f"\n{Fore.CYAN}🔌 API Endpoints detectados:{Style.RESET_ALL}")
    for ep in security_info.get('api_endpoints', [])[:20]:
        print(f"  • {ep}")

    print(f"\n{Fore.CYAN}📡 WebSockets:{Style.RESET_ALL}")
    for ws in security_info.get('websockets', []):
        print(f"  • {ws}")

    print(f"\n{Fore.CYAN}💾 LocalStorage / SessionStorage keys:{Style.RESET_ALL}")
    if security_info.get('storage_keys'):
        print(f"  {', '.join(security_info.get('storage_keys')[:20])}")

    # JS params
    js_params = security_info.get('js_parameters', [])
    if js_params:
        print(f"\n{Fore.CYAN}🔎 Parámetros heurísticos en JS ({len(js_params)}):{Style.RESET_ALL}")
        print(f"  {', '.join(js_params[:20])}" + (f"... y {len(js_params)-20} más" if len(js_params) > 20 else ""))

    # Inputs descubiertos
    print(f"\n{Fore.MAGENTA}🎯 Inputs Descubiertos:{Style.RESET_ALL}")
    if not discovered_inputs:
        print(f"{Fore.YELLOW}  No se encontraron inputs en la profundidad especificada.{Style.RESET_ALL}")
    else:
        for i, inp in enumerate(discovered_inputs, 1):
            print(f"\n{Fore.WHITE}{Style.BRIGHT}  ───────── Input {i} ─────────{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}URL de Origen:{Style.RESET_ALL} {inp.get('url')}")
            print(f"  {Fore.CYAN}Tipo:{Style.RESET_ALL} {inp.get('type')}")
            if inp.get('type') == 'GET_URL_PARAMS':
                print(f"  {Fore.CYAN}Parámetros:{Style.RESET_ALL}")
                for param, vals in inp.get('parameters', {}).items():
                    print(f"    • {param}: {vals}")
            else:
                print(f"  {Fore.CYAN}Acción:{Style.RESET_ALL} {inp.get('form_action')}")
                fields = inp.get('fields', [])
                print(f"  {Fore.CYAN}Campos ({len(fields)}):{Style.RESET_ALL}")
                for f in fields:
                    hidden_marker = f" {Fore.YELLOW}[OCULTO]{Style.RESET_ALL}" if f.get('hidden') else ""
                    valinfo = f" = '{f.get('value')}'" if f.get('value') else ""
                    print(f"    • {f.get('name')} ({f.get('type')}){valinfo}{hidden_marker}")

    print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")

def export_results(results, format_type='json', filename=None):
    """
    Exporta resultados a JSON o TXT.
    Si filename es None, genera uno con timestamp.
    """
    if not results:
        print(f"{Fore.RED}[-] No hay resultados para exportar.{Style.RESET_ALL}")
        return

    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{ts}.{format_type}"

    try:
        if format_type == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        elif format_type == 'txt':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("REPORTE DE RASTREO WEB\n")
                f.write("="*60 + "\n\n")
                f.write(f"Fecha: {results.get('scan_date')}\n")
                f.write(f"URLs visitadas: {len(results.get('visited_urls', []))}\n")
                f.write(f"Inputs descubiertos: {len(results.get('discovered_inputs', []))}\n\n")
                f.write("INFORMACIÓN DE SEGURIDAD\n")
                f.write("-"*60 + "\n")
                wafs = results.get('security_info', {}).get('waf_detected', [])
                f.write(f"WAF: {', '.join(wafs) if wafs else 'No detectado'}\n")
                techs = results.get('security_info', {}).get('technologies', [])
                f.write(f"Tecnologías: {', '.join(techs)}\n\n")
                f.write("INPUTS DESCUBIERTOS\n")
                f.write("-"*60 + "\n")
                for i, inp in enumerate(results.get('discovered_inputs', []), 1):
                    f.write(f"\nInput {i}:\n")
                    f.write(f"  URL: {inp.get('url')}\n")
                    f.write(f"  Tipo: {inp.get('type')}\n")
                    if inp.get('type') == 'GET_URL_PARAMS':
                        f.write(f"  Parámetros: {inp.get('parameters')}\n")
                    else:
                        f.write(f"  Acción: {inp.get('form_action')}\n")
                        f.write(f"  Campos: {[field.get('name') for field in inp.get('fields', [])]}\n")
        print(f"{Fore.GREEN}[+] Resultados exportados a: {filename}{Style.RESET_ALL}")
        logging.info(f"Resultados exportados a {filename}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error al exportar resultados: {e}{Style.RESET_ALL}")
        logging.error(f"Error al exportar: {e}")

# -----------------------
# CLI y main
# -----------------------

def main():
    parser = argparse.ArgumentParser(
        description="Herramienta avanzada de reconocimiento web para identificar inputs y analizar seguridad.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python %(prog)s -u https://ejemplo.com
  python %(prog)s -u https://ejemplo.com -d 3 --delay 1.0 --max-urls 500
  python %(prog)s -u https://ejemplo.com --export json --output resultados.json
  python %(prog)s -u https://ejemplo.com --no-verify --quiet --log scan.log
"""
    )

    parser.add_argument('-u', '--url', required=True, help="URL objetivo para el rastreo")
    parser.add_argument('-d', '--depth', type=int, default=MAX_DEPTH_DEFAULT,
                        help=f"Profundidad máxima de rastreo (por defecto: {MAX_DEPTH_DEFAULT})")
    parser.add_argument('--max-urls', type=int, default=MAX_URLS_DEFAULT,
                        help=f"Número máximo de URLs a visitar (por defecto: {MAX_URLS_DEFAULT})")
    parser.add_argument('--delay', type=float, default=0.5,
                        help="Delay en segundos entre peticiones (por defecto: 0.5)")
    parser.add_argument('--no-verify', action='store_true',
                        help="Deshabilitar verificación SSL (útil para entornos de prueba)")
    parser.add_argument('--no-robots', action='store_true',
                        help="No verificar robots.txt")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Modo silencioso (solo muestra errores)")
    parser.add_argument('--export', choices=['json', 'txt'],
                        help="Formato de exportación de resultados")
    parser.add_argument('-o', '--output',
                        help="Nombre del archivo de salida")
    parser.add_argument('--log',
                        help="Archivo para guardar logs")

    args = parser.parse_args()

    # Configurar logging
    setup_logging(quiet_mode=args.quiet, log_file=args.log)

    # Banner
    if not args.quiet:
        print(f"{Fore.GREEN}{Style.BRIGHT}")
        print("="*60)
        print("  DETECTOR DE INPUTS WEB - v2.0")
        print("  Herramienta de Reconocimiento Avanzado")
        print("="*60)
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Asegúrate de tener autorización antes de escanear cualquier sitio web{Style.RESET_ALL}\n")

    # Ejecutar rastreo usando la versión mejorada
    results = advanced_crawler_enhanced(
        start_url=args.url,
        max_depth=args.depth,
        max_urls=args.max_urls,
        verify_ssl=not args.no_verify,
        delay=args.delay,
        check_robots=not args.no_robots,
        quiet=args.quiet
    )

    if results:
        if not args.quiet:
            print_report_enhanced(results, quiet=args.quiet)

        # Exportar si se solicitó
        if args.export:
            export_results(results, format_type=args.export, filename=args.output)
        logging.info("Rastreo completado exitosamente")
    else:
        print(f"{Fore.RED}[-] El rastreo falló. Revisa los logs para más información.{Style.RESET_ALL}")
        logging.error("El rastreo no produjo resultados")

if __name__ == '__main__':
    main()

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

# Inicializar colorama
init(autoreset=True)

# --- Configuración y Constantes ---
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

# Extensiones de archivo a excluir
EXCLUDED_EXTENSIONS = ['.pdf', '.zip', '.exe', '.jpg', '.jpeg', '.png', '.gif', 
                       '.mp4', '.mp3', '.avi', '.mov', '.css', '.js', '.ico',
                       '.svg', '.woff', '.woff2', '.ttf', '.eot']

# Límites de seguridad
MAX_URLS_DEFAULT = 1000
MAX_DEPTH_DEFAULT = 2

# Headers de seguridad a verificar
SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy'
]

# Indicadores de tecnologías
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

# --- Configuración de Logging ---
def setup_logging(quiet_mode=False, log_file=None):
    """Configura el sistema de logging"""
    if log_file:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if not quiet_mode else logging.NullHandler()
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO if not quiet_mode else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

# --- Funciones de Utilidad ---
def should_skip_url(url):
    """Verifica si la URL debe ser omitida por su extensión"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS)

def detect_waf(response):
    """Detecta posibles Web Application Firewalls"""
    waf_headers = {
        'cloudflare': ['cf-ray', 'cloudflare'],
        'akamai': ['akamai'],
        'incapsula': ['incap_ses', 'visid_incap'],
        'sucuri': ['sucuri', 'x-sucuri'],
        'aws-waf': ['x-amzn-requestid', 'x-amz-cf-id']
    }
    
    detected = []
    response_headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    
    for waf_name, indicators in waf_headers.items():
        for indicator in indicators:
            if any(indicator in header for header in response_headers_lower):
                detected.append(waf_name)
                break
    
    return list(set(detected))

def check_security_headers(response):
    """Verifica la presencia de headers de seguridad"""
    missing_headers = []
    present_headers = {}
    
    for header in SECURITY_HEADERS:
        if header in response.headers:
            present_headers[header] = response.headers[header]
        else:
            missing_headers.append(header)
    
    return {'missing': missing_headers, 'present': present_headers}

def detect_technologies(html_content, response_headers):
    """Detecta tecnologías y frameworks utilizados"""
    detected_tech = []
    content_lower = html_content.lower()
    
    for tech, indicators in TECH_INDICATORS.items():
        for indicator in indicators:
            if indicator.lower() in content_lower:
                detected_tech.append(tech)
                break
    
    # Detectar por headers
    server = response_headers.get('Server', '').lower()
    if 'nginx' in server:
        detected_tech.append('Nginx')
    elif 'apache' in server:
        detected_tech.append('Apache')
    elif 'iis' in server:
        detected_tech.append('IIS')
    
    x_powered = response_headers.get('X-Powered-By', '').lower()
    if 'php' in x_powered:
        detected_tech.append('PHP')
    elif 'asp.net' in x_powered:
        detected_tech.append('ASP.NET')
    
    return list(set(detected_tech))

def find_js_params(html_content):
    """Busca parámetros potenciales en código JavaScript"""
    patterns = [
        r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # Parámetros en URLs
        r'\.get\(["\']([^"\']+)["\']\)',    # .get() methods
        r'param[s]?\[["\'"]([^"\']+)["\'"]',  # params[] o param[]
        r'data\[["\'"]([^"\']+)["\'"]',     # data[] accesos
    ]
    
    found_params = set()
    for pattern in patterns:
        matches = re.findall(pattern, html_content)
        found_params.update(matches)
    
    return list(found_params)

def check_robots_txt(base_url):
    """Verifica y parsea el archivo robots.txt"""
    robots_url = urljoin(base_url, '/robots.txt')
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            disallowed_paths = []
            for line in response.text.split('\n'):
                if line.strip().lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        disallowed_paths.append(path)
            return {'exists': True, 'disallowed': disallowed_paths}
    except:
        pass
    return {'exists': False, 'disallowed': []}

# --- Funciones Principales ---
def get_page_content(url, verify_ssl=True, delay=0):
    """
    Realiza una solicitud HTTP GET con manejo avanzado de errores
    """
    try:
        if delay > 0:
            time.sleep(delay)
        
        current_headers = BASE_HEADERS.copy()
        current_headers['User-Agent'] = random.choice(USER_AGENTS)

        if not args.quiet:
            print(f"{Fore.CYAN}[*] Obteniendo: {url}{Style.RESET_ALL}")
        
        logging.info(f"Solicitando: {url}")
        response = requests.get(url, headers=current_headers, timeout=10, verify=verify_ssl)
        response.raise_for_status()
        
        return response
    except requests.exceptions.SSLError as e:
        logging.warning(f"Error SSL en {url}: {e}")
        if not args.quiet:
            print(f"{Fore.YELLOW}[!] Error SSL en {url} - Intenta con --no-verify{Style.RESET_ALL}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al obtener {url}: {e}")
        if not args.quiet:
            print(f"{Fore.RED}[-] Error al obtener {url}: {e}{Style.RESET_ALL}")
        return None

def extract_internal_links(base_url, html_content):
    """Extrae enlaces internos del HTML"""
    internal_links = set()
    if not html_content:
        return internal_links

    soup = BeautifulSoup(html_content, 'html.parser')
    base_netloc = urlparse(base_url).netloc

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)

        if parsed_url.netloc == base_netloc and parsed_url.scheme in ['http', 'https']:
            if not should_skip_url(full_url):
                normalized_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
                if parsed_url.query:
                    normalized_url += "?" + parsed_url.query
                internal_links.add(normalized_url)

    return internal_links

def identify_get_parameters(url):
    """Identifica parámetros GET en una URL"""
    parsed_url = urlparse(url)
    query_string = parsed_url.query
    if not query_string:
        return {}
    
    parameters = parse_qs(query_string)
    return parameters

def extract_form_inputs(base_url, html_content):
    """Extrae información detallada de formularios"""
    forms = []
    if not html_content:
        return forms

    soup = BeautifulSoup(html_content, 'html.parser')

    for form_tag in soup.find_all('form'):
        form_action = form_tag.get('action', '')
        full_action_url = urljoin(base_url, form_action)
        form_method = form_tag.get('method', 'GET').upper()
        
        form_fields = []
        
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            field_name = input_tag.get('name')
            if field_name:
                field_info = {
                    'name': field_name,
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'hidden': input_tag.get('type') == 'hidden'
                }
                form_fields.append(field_info)
        
        if form_fields:
            forms.append({
                'action': full_action_url,
                'method': form_method,
                'fields': form_fields
            })

    return forms

def extract_cookies(response):
    """Extrae cookies que pueden ser vectores de ataque"""
    cookies = []
    for cookie in response.cookies:
        cookie_data = {
            'name': cookie.name,
            'value': cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly')
        }
        cookies.append(cookie_data)
    return cookies

def extract_api_endpoints(html_content):
    """Detecta posibles endpoints API en código JavaScript"""
    api_patterns = [
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'/api/[a-zA-Z0-9/_-]+',
        r'/v\d+/[a-zA-Z0-9/_-]+',  # endpoints versionados
    ]
    
    endpoints = set()
    for pattern in api_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        endpoints.update(matches)
    
    return list(endpoints)

def extract_custom_headers(html_content):
    """Busca referencias a headers HTTP personalizados en JS"""
    header_patterns = [
        r'headers:\s*{([^}]+)}',
        r'setRequestHeader\(["\']([^"\']+)["\']',
        r'Authorization["\']:\s*["\']([^"\']+)["\']',
    ]
    
    headers = set()
    for pattern in header_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            # Extraer nombres de headers
            header_names = re.findall(r'["\']([A-Za-z-]+)["\']', match)
            headers.update(header_names)
    
    return list(headers)

def analyze_input_validation(form_fields):
    """Analiza atributos de validación client-side"""
    validation_info = []
    
    for field in form_fields:
        field_validation = {
            'name': field['name'],
            'type': field['type'],
            'validations': {}
        }
        
        # Atributos HTML5 de validación
        validation_attrs = [
            'required', 'pattern', 'minlength', 'maxlength', 
            'min', 'max', 'step', 'accept'
        ]
        
        for attr in validation_attrs:
            if attr in field:
                field_validation['validations'][attr] = field[attr]
        
        if field_validation['validations']:
            validation_info.append(field_validation)
    
    return validation_info

def extract_enhanced_form_inputs(base_url, html_content):
    """Versión mejorada que captura más detalles"""
    forms = []
    if not html_content:
        return forms

    soup = BeautifulSoup(html_content, 'html.parser')

    for form_tag in soup.find_all('form'):
        form_action = form_tag.get('action', '')
        full_action_url = urljoin(base_url, form_action)
        form_method = form_tag.get('method', 'GET').upper()
        form_enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
        
        form_fields = []
        
        # Incluir también buttons con name (nuevo)
        for input_tag in form_tag.find_all(['input', 'textarea', 'select', 'button']):
            field_name = input_tag.get('name')
            if field_name:
                field_info = {
                    'name': field_name,
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'hidden': input_tag.get('type') == 'hidden',
                    # Atributos de validación (nuevo)
                    'required': input_tag.has_attr('required'),
                    'pattern': input_tag.get('pattern', ''),
                    'minlength': input_tag.get('minlength', ''),
                    'maxlength': input_tag.get('maxlength', ''),
                    'accept': input_tag.get('accept', ''),  # Para file uploads
                }
                form_fields.append(field_info)
        
        if form_fields:
            forms.append({
                'action': full_action_url,
                'method': form_method,
                'enctype': form_enctype,  # Importante para file uploads
                'fields': form_fields,
                'has_file_upload': any(f['type'] == 'file' for f in form_fields)
            })

    return forms

def detect_json_payloads(html_content):
    """Detecta estructuras JSON que se envían en peticiones"""
    json_patterns = [
        r'JSON\.stringify\(({[^}]+})\)',
        r'data:\s*({[^}]+})',
        r'body:\s*JSON\.stringify\(([^)]+)\)',
    ]
    
    json_structures = []
    for pattern in json_patterns:
        matches = re.findall(pattern, html_content, re.DOTALL)
        json_structures.extend(matches)
    
    return json_structures

def detect_websockets(html_content):
    """Detecta uso de WebSockets"""
    ws_pattern = r'new\s+WebSocket\(["\']([^"\']+)["\']'
    matches = re.findall(ws_pattern, html_content)
    return matches

def detect_localstorage_usage(html_content):
    """Detecta uso de localStorage/sessionStorage como fuente de datos"""
    storage_patterns = [
        r'localStorage\.getItem\(["\']([^"\']+)["\']',
        r'sessionStorage\.getItem\(["\']([^"\']+)["\']',
        r'localStorage\[["\']([^"\']+)["\']',
    ]
    
    storage_keys = set()
    for pattern in storage_patterns:
        matches = re.findall(pattern, html_content)
        storage_keys.update(matches)
    
    return list(storage_keys)

# --- Función de Rastreo Mejorado ---
def advanced_crawler_enhanced(start_url, max_depth=2, max_urls=1000, verify_ssl=True, delay=0, check_robots=True):
    """
    Versión mejorada con detección completa según WSTG
    """
    # Validación de URL
    if not start_url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[-] La URL debe comenzar con http:// o https://{Style.RESET_ALL}")
        return None
    
    visited_urls = set()
    urls_to_visit = [(start_url, 0)]
    discovered_inputs = []
    security_info = {
        'waf_detected': [],
        'security_headers': {},
        'technologies': [],
        'robots_txt': {},
        'js_parameters': [],
        'cookies': [],  # NUEVO
        'api_endpoints': [],  # NUEVO
        'custom_headers': [],  # NUEVO
        'websockets': [],  # NUEVO
        'storage_keys': [],  # NUEVO
        'json_payloads': []  # NUEVO
    }

    # Verificar robots.txt si está habilitado
    if check_robots:
        if not args.quiet:
            print(f"{Fore.CYAN}[*] Verificando robots.txt...{Style.RESET_ALL}")
        security_info['robots_txt'] = check_robots_txt(start_url)
        if security_info['robots_txt']['exists']:
            logging.info(f"robots.txt encontrado con {len(security_info['robots_txt']['disallowed'])} rutas bloqueadas")

    if not args.quiet:
        print(f"{Fore.GREEN}[+] Iniciando rastreo: {start_url}")
        print(f"[+] Profundidad máxima: {max_depth}")
        print(f"[+] Límite de URLs: {max_urls}")
        print(f"[+] Delay entre peticiones: {delay}s")
        print(f"[+] Verificación SSL: {'Activada' if verify_ssl else 'Desactivada'}{Style.RESET_ALL}\n")

    first_request = True

    while urls_to_visit:
        if len(visited_urls) >= max_urls:
            if not args.quiet:
                print(f"{Fore.YELLOW}[!] Límite de URLs alcanzado ({max_urls}){Style.RESET_ALL}")
            logging.warning(f"Límite de URLs alcanzado: {max_urls}")
            break

        current_url, current_depth = urls_to_visit.pop(0)

        if current_url in visited_urls or current_depth > max_depth:
            continue

        if not args.quiet:
            print(f"{Fore.BLUE}[+] Visitando: {current_url} (Profundidad: {current_depth}){Style.RESET_ALL}")
        
        visited_urls.add(current_url)

        # Identificar parámetros GET
        get_params = identify_get_parameters(current_url)
        if get_params:
            discovered_inputs.append({
                'url': current_url,
                'type': 'GET_URL_PARAMS',
                'parameters': get_params
            })

        # Obtener contenido
        if current_depth < max_depth:
            response = get_page_content(current_url, verify_ssl, delay if not first_request else 0)
            first_request = False
            
             if response:
                html_content = response.text
        
                # Extraer cookies (NUEVO)
                cookies = extract_cookies(response)
                security_info['cookies'].extend(cookies)
                
                # Detectar API endpoints (NUEVO)
                api_endpoints = extract_api_endpoints(html_content)
                security_info['api_endpoints'].extend(api_endpoints)
                
                # Detectar custom headers (NUEVO)
                custom_headers = extract_custom_headers(html_content)
                security_info['custom_headers'].extend(custom_headers)
                
                # Detectar WebSockets (NUEVO)
                websockets = detect_websockets(html_content)
                security_info['websockets'].extend(websockets)
                
                # Detectar localStorage usage (NUEVO)
                storage_keys = detect_localstorage_usage(html_content)
                security_info['storage_keys'].extend(storage_keys)
                
                # Detectar JSON payloads (NUEVO)
                json_payloads = detect_json_payloads(html_content)
                security_info['json_payloads'].extend(json_payloads)
                
                # Análisis de seguridad en la primera página
                if current_url == start_url or not security_info['waf_detected']:
                    waf = detect_waf(response)
                    if waf:
                        security_info['waf_detected'].extend(waf)
                        if not args.quiet:
                            print(f"{Fore.YELLOW}[!] WAF Detectado: {', '.join(waf)}{Style.RESET_ALL}")
                
                if current_url == start_url:
                    security_info['security_headers'] = check_security_headers(response)
                    security_info['technologies'] = detect_technologies(html_content, response.headers)
                    
                    if not args.quiet and security_info['technologies']:
                        print(f"{Fore.CYAN}[*] Tecnologías detectadas: {', '.join(security_info['technologies'])}{Style.RESET_ALL}")
                
                # Buscar parámetros en JavaScript
                js_params = find_js_params(html_content)
                if js_params:
                    security_info['js_parameters'].extend(js_params)
                
                # Extraer enlaces
                new_links = extract_internal_links(current_url, html_content)
                for link in new_links:
                    if link not in visited_urls:
                        urls_to_visit.append((link, current_depth + 1))
                
                # Extraer formularios
                forms = extract_enhanced_form_inputs(current_url, html_content)
                for form in forms:
                    input_type = f"FORM_{form['method']}"
                    discovered_inputs.append({
                        'url': current_url,
                        'form_action': form['action'],
                        'type': input_type,
                        'fields': form['fields']
                    })

    # Eliminar duplicados de parámetros JS
    security_info['js_parameters'] = list(set(security_info['js_parameters']))
    security_info['waf_detected'] = list(set(security_info['waf_detected']))

    return {
        'visited_urls': list(visited_urls),
        'discovered_inputs': discovered_inputs,
        'security_info': security_info,
        'scan_date': datetime.now().isoformat()
    }



# --- Funciones de Reporte ---
def print_report_enhanced(results):
    """Versión mejorada del reporte"""
    if not results:
        return
    
    # Información de seguridad
    print(f"\n{Fore.CYAN}🛡️  Información de Seguridad:{Style.RESET_ALL}")
    
    if security_info['waf_detected']:
        print(f"  • WAF Detectado: {Fore.YELLOW}{', '.join(security_info['waf_detected'])}{Style.RESET_ALL}")
    else:
        print(f"  • WAF Detectado: {Fore.GREEN}No detectado{Style.RESET_ALL}")
    
    if security_info['technologies']:
        print(f"  • Tecnologías: {', '.join(security_info['technologies'])}")
    
    if security_info['robots_txt']['exists']:
        print(f"  • robots.txt: {Fore.GREEN}Presente{Style.RESET_ALL} ({len(security_info['robots_txt']['disallowed'])} rutas bloqueadas)")
    else:
        print(f"  • robots.txt: {Fore.YELLOW}No encontrado{Style.RESET_ALL}")
    
    # Headers de seguridad
    missing_headers = security_info['security_headers'].get('missing', [])
    if missing_headers:
        print(f"  • Headers de seguridad faltantes ({len(missing_headers)}):")
        for header in missing_headers:
            print(f"    - {Fore.RED}{header}{Style.RESET_ALL}")
    else:
        print(f"  • Headers de seguridad: {Fore.GREEN}Todos presentes{Style.RESET_ALL}")

      # Nuevas secciones:
    security_info = results['security_info']
    
    print(f"\n{Fore.CYAN}🍪 Cookies Detectadas:{Style.RESET_ALL}")
    if security_info['cookies']:
        for cookie in security_info['cookies'][:5]:  # Mostrar primeras 5
            secure_flag = f"{Fore.GREEN}Secure{Style.RESET_ALL}" if cookie['secure'] else f"{Fore.RED}No Secure{Style.RESET_ALL}"
            httponly_flag = f"{Fore.GREEN}HttpOnly{Style.RESET_ALL}" if cookie['httponly'] else f"{Fore.RED}No HttpOnly{Style.RESET_ALL}"
            print(f"  • {cookie['name']}: {secure_flag}, {httponly_flag}")
    
    print(f"\n{Fore.CYAN}🔌 API Endpoints:{Style.RESET_ALL}")
    if security_info['api_endpoints']:
        for endpoint in security_info['api_endpoints'][:10]:
            print(f"  • {endpoint}")
    
    print(f"\n{Fore.CYAN}📡 WebSockets:{Style.RESET_ALL}")
    if security_info['websockets']:
        for ws in security_info['websockets']:
            print(f"  • {ws}")
    
    print(f"\n{Fore.CYAN}💾 LocalStorage Keys:{Style.RESET_ALL}")
    if security_info['storage_keys']:
        print(f"  {', '.join(security_info['storage_keys'][:10])}")

    
    visited_urls = results['visited_urls']
    discovered_inputs = results['discovered_inputs']
    security_info = results['security_info']
    
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{'REPORTE DE RASTREO':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}📊 Estadísticas:{Style.RESET_ALL}")
    print(f"  • URLs visitadas: {len(visited_urls)}")
    print(f"  • Inputs descubiertos: {len(discovered_inputs)}")
    print(f"  • Fecha del escaneo: {results['scan_date']}")
    
    # Parámetros en JavaScript
    if security_info['js_parameters']:
        print(f"  • Parámetros encontrados en JS: {len(security_info['js_parameters'])}")
        print(f"    {', '.join(security_info['js_parameters'][:10])}" + 
              (f"... y {len(security_info['js_parameters']) - 10} más" if len(security_info['js_parameters']) > 10 else ""))
    
    # Inputs descubiertos
    print(f"\n{Fore.MAGENTA}🎯 Inputs Descubiertos:{Style.RESET_ALL}")
    
    if not discovered_inputs:
        print(f"{Fore.YELLOW}  No se encontraron inputs inyectables en la profundidad especificada.{Style.RESET_ALL}")
    else:
        for i, input_data in enumerate(discovered_inputs, 1):
            print(f"\n{Fore.WHITE}{Style.BRIGHT}  ──────────────── Input {i} ────────────────{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}URL de Origen:{Style.RESET_ALL} {input_data['url']}")
            print(f"  {Fore.CYAN}Tipo:{Style.RESET_ALL} {input_data['type']}")
            
            if input_data['type'] == 'GET_URL_PARAMS':
                print(f"  {Fore.CYAN}Parámetros:{Style.RESET_ALL}")
                for param, values in input_data['parameters'].items():
                    print(f"    • {param}: {values}")
            else:
                print(f"  {Fore.CYAN}Acción:{Style.RESET_ALL} {input_data['form_action']}")
                print(f"  {Fore.CYAN}Campos ({len(input_data['fields'])}):{Style.RESET_ALL}")
                for field in input_data['fields']:
                    hidden_marker = f" {Fore.YELLOW}[OCULTO]{Style.RESET_ALL}" if field.get('hidden') else ""
                    value_info = f" = '{field.get('value')}'" if field.get('value') else ""
                    print(f"    • {field['name']} ({field['type']}){value_info}{hidden_marker}")
    
    print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")

def export_results(results, format_type='json', filename=None):
    """Exporta los resultados en diferentes formatos"""
    if not results:
        return
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.{format_type}"
    
    try:
        if format_type == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        
        elif format_type == 'txt':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("REPORTE DE RASTREO WEB\n")
                f.write("="*60 + "\n\n")
                f.write(f"Fecha: {results['scan_date']}\n")
                f.write(f"URLs visitadas: {len(results['visited_urls'])}\n")
                f.write(f"Inputs descubiertos: {len(results['discovered_inputs'])}\n\n")
                
                f.write("INFORMACIÓN DE SEGURIDAD\n")
                f.write("-"*60 + "\n")
                f.write(f"WAF: {', '.join(results['security_info']['waf_detected']) or 'No detectado'}\n")
                f.write(f"Tecnologías: {', '.join(results['security_info']['technologies'])}\n\n")
                
                f.write("INPUTS DESCUBIERTOS\n")
                f.write("-"*60 + "\n")
                for i, inp in enumerate(results['discovered_inputs'], 1):
                    f.write(f"\nInput {i}:\n")
                    f.write(f"  URL: {inp['url']}\n")
                    f.write(f"  Tipo: {inp['type']}\n")
                    if inp['type'] == 'GET_URL_PARAMS':
                        f.write(f"  Parámetros: {inp['parameters']}\n")
                    else:
                        f.write(f"  Acción: {inp['form_action']}\n")
                        f.write(f"  Campos: {[field['name'] for field in inp['fields']]}\n")
        
        print(f"{Fore.GREEN}[+] Resultados exportados a: {filename}{Style.RESET_ALL}")
        logging.info(f"Resultados exportados a {filename}")
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error al exportar resultados: {e}{Style.RESET_ALL}")
        logging.error(f"Error al exportar: {e}")

# --- Main ---
if __name__ == "__main__":
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

    # Ejecutar rastreo
    results = advanced_crawler(
        start_url=args.url,
        max_depth=args.depth,
        max_urls=args.max_urls,
        verify_ssl=not args.no_verify,
        delay=args.delay,
        check_robots=not args.no_robots
    )

    if results:
        # Mostrar reporte
        if not args.quiet:
            print_report(results)
        
        # Exportar si se solicitó
        if args.export:
            export_results(results, format_type=args.export, filename=args.output)
        
        logging.info("Rastreo completado exitosamente")
    else:
        print(f"{Fore.RED}[-] El rastreo falló. Revisa los logs para más información.{Style.RESET_ALL}")
        logging.error("El rastreo no produjo resultados")

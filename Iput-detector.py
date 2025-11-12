import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import random
from colorama import init, Fore, Style # Importar para colores en la consola

# Inicializar colorama para que funcione en diferentes terminales
init(autoreset=True)

# --- Configuración y Constantes ---
# Lista de User-Agents comunes para rotación
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 13; Mobile; rv:107.0) Gecko/107.0 Firefox/107.0',
]

# Cabeceras HTTP base
BASE_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
    'DNT': '1', # Do Not Track Request Header
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# --- Funciones Principales ---

def get_page_content(url):
    """
    Realiza una solicitud HTTP GET a la URL especificada y devuelve el contenido HTML.
    Utiliza un User-Agent aleatorio para cada solicitud.
    Maneja posibles errores de conexión.

    Args:
        url (str): La URL a la que se realizará la solicitud.

    Returns:
        str: El contenido HTML de la página si la solicitud es exitosa, None en caso contrario.
    """
    try:
        # Seleccionar un User-Agent aleatorio para esta solicitud
        current_headers = BASE_HEADERS.copy()
        current_headers['User-Agent'] = random.choice(USER_AGENTS)

        print(f"{Fore.CYAN}[*] Obteniendo contenido de: {url} (User-Agent: {current_headers['User-Agent'][:30]}...){Style.RESET_ALL}")
        response = requests.get(url, headers=current_headers, timeout=10) # Timeout de 10 segundos
        response.raise_for_status() # Lanza un error para códigos de estado HTTP 4xx/5xx
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error al obtener {url}: {e}{Style.RESET_ALL}")
        return None

def extract_internal_links(base_url, html_content):
    """
    Extrae todos los enlaces internos (dentro del mismo dominio) de un contenido HTML.

    Args:
        base_url (str): La URL base de la página actual para resolver enlaces relativos.
        html_content (str): El contenido HTML de la página.

    Returns:
        set: Un conjunto de URLs internas únicas.
    """
    internal_links = set()
    if not html_content:
        return internal_links

    soup = BeautifulSoup(html_content, 'html.parser')
    base_netloc = urlparse(base_url).netloc # Dominio de la URL base

    # Buscar todas las etiquetas 'a' (enlaces)
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # Resolver URL relativa a absoluta
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)

        # Verificar si el enlace pertenece al mismo dominio y es HTTP/HTTPS
        if parsed_url.netloc == base_netloc and parsed_url.scheme in ['http', 'https']:
            # Normalizar la URL para evitar duplicados por fragmentos (#)
            normalized_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
            if parsed_url.query:
                normalized_url += "?" + parsed_url.query
            internal_links.add(normalized_url)

    return internal_links

def identify_get_parameters(url):
    """
    Identifica los parámetros GET de una URL.

    Args:
        url (str): La URL a analizar.

    Returns:
        dict: Un diccionario donde las claves son los nombres de los parámetros
              y los valores son una lista de sus valores.
              Retorna un diccionario vacío si no hay parámetros GET.
    """
    parsed_url = urlparse(url)
    query_string = parsed_url.query
    if not query_string:
        return {}

    # parse_qs devuelve un diccionario donde los valores son listas (puede haber múltiples valores para un mismo parámetro)
    parameters = parse_qs(query_string)
    return parameters

def extract_form_inputs(base_url, html_content):
    """
    Extrae información de formularios (action, method, campos de entrada) de un contenido HTML.
    Se enfoca en formularios con métodos POST y GET.

    Args:
        base_url (str): La URL base para resolver la acción del formulario.
        html_content (str): El contenido HTML de la página.

    Returns:
        list: Una lista de diccionarios, donde cada diccionario representa un formulario
              con 'action', 'method' y 'fields'.
    """
    forms = []
    if not html_content:
        return forms

    soup = BeautifulSoup(html_content, 'html.parser')

    for form_tag in soup.find_all('form'):
        form_action = form_tag.get('action', '')
        # Resolver la URL de acción del formulario
        full_action_url = urljoin(base_url, form_action)

        form_method = form_tag.get('method', 'GET').upper() # Por defecto GET si no se especifica
        
        form_fields = []
        # Buscar campos de entrada comunes
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            field_name = input_tag.get('name')
            if field_name:
                form_fields.append(field_name)
        
        # Solo añadimos formularios que tengan campos y sean POST
        if form_fields and form_method == 'POST':
             forms.append({
                'action': full_action_url,
                'method': form_method,
                'fields': form_fields
            })
        # Si es un formulario GET, solo lo añadimos si tiene campos explícitos que no sean ya parte de la URL
        # Esto es para evitar duplicar el reporte de parámetros GET ya identificados por identify_get_parameters
        elif form_fields and form_method == 'GET':
            # Para formularios GET, los parámetros ya están en la URL o son explícitos en el formulario.
            # Aquí nos enfocamos en los que tienen campos explícitos.
            forms.append({
                'action': full_action_url,
                'method': form_method,
                'fields': form_fields
            })


    return forms

# --- Función de Rastreo Básico ---

def simple_crawler(start_url, max_depth=2):
    """
    Realiza un rastreo básico del sitio web a partir de una URL de inicio,
    identificando enlaces, parámetros GET y formularios (POST/GET).

    Args:
        start_url (str): La URL de inicio para el rastreo.
        max_depth (int): La profundidad máxima de rastreo.
    """
    visited_urls = set()
    urls_to_visit = [(start_url, 0)] # (url, depth)
    discovered_inputs = [] # Lista para almacenar los inputs encontrados

    print(f"{Fore.GREEN}[+] Iniciando rastreo para: {start_url} con profundidad máxima: {max_depth}{Style.RESET_ALL}\n")

    while urls_to_visit:
        current_url, current_depth = urls_to_visit.pop(0) # BFS

        if current_url in visited_urls or current_depth > max_depth:
            continue

        print(f"{Fore.BLUE}[+] Visitando: {current_url} (Profundidad: {current_depth}){Style.RESET_ALL}")
        visited_urls.add(current_url)

        # Identificar parámetros GET de la URL
        get_params = identify_get_parameters(current_url)
        if get_params:
            discovered_inputs.append({
                'url': current_url,
                'type': 'GET_URL_PARAMS',
                'parameters': get_params
            })

        # Obtener contenido y extraer enlaces y formularios si no hemos alcanzado la profundidad máxima
        if current_depth < max_depth:
            html_content = get_page_content(current_url)
            if html_content:
                # Extraer enlaces para continuar el rastreo
                new_links = extract_internal_links(current_url, html_content)
                for link in new_links:
                    if link not in visited_urls:
                        urls_to_visit.append((link, current_depth + 1))
                
                # Extraer formularios (GET, POST)
                forms = extract_form_inputs(current_url, html_content)
                for form in forms:
                    input_type = f"FORM_{form['method']}"
                    discovered_inputs.append({
                        'url': current_url,
                        'form_action': form['action'],
                        'type': input_type,
                        'fields': form['fields']
                    })

    # --- Reporte Final Estilizado ---
    print(f"\n{Fore.MAGENTA}--- Rastreo Completado ---{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}URLs visitadas: {len(visited_urls)}{Style.RESET_ALL}")
    print(f"\n{Fore.MAGENTA}--- Inputs Descubiertos ---{Style.RESET_ALL}")

    if not discovered_inputs:
        print(f"{Fore.YELLOW}No se encontraron inputs inyectables en la profundidad especificada.{Style.RESET_ALL}")
    else:
        for i, input_data in enumerate(discovered_inputs):
            print(f"{Fore.WHITE}{Style.BRIGHT}-------------------- Input {i+1} --------------------{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  URL de Origen:{Style.RESET_ALL} {input_data['url']}")
            print(f"{Fore.CYAN}  Tipo de Input:{Style.RESET_ALL} {input_data['type']}")
            if input_data['type'] == 'GET_URL_PARAMS':
                print(f"{Fore.CYAN}  Parámetros:{Style.RESET_ALL} {input_data['parameters']}")
            else: # FORM_GET, FORM_POST
                print(f"{Fore.CYAN}  Acción del Formulario:{Style.RESET_ALL} {input_data['form_action']}")
                print(f"{Fore.CYAN}  Campos del Formulario:{Style.RESET_ALL} {input_data['fields']}")
            print(f"{Fore.WHITE}{Style.BRIGHT}---------------------------------------------------{Style.RESET_ALL}")


# --- Ejemplo de Uso (Modificado para argparse) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramienta de reconocimiento web para identificar inputs.")
    parser.add_argument('-u', '--url', required=True, help="La URL objetivo para el rastreo.")
    parser.add_argument('-d', '--depth', type=int, default=2, help="Profundidad máxima de rastreo (por defecto: 2).")

    args = parser.parse_args()

    target_url = args.url
    max_depth = args.depth

    # ¡RECUERDA SIEMPRE TENER PERMISO PARA AUDITAR UN SITIO!
    simple_crawler(target_url, max_depth=max_depth)

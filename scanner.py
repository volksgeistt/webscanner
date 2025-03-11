import os
import sys
import requests
import socket
import ssl
import json
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import subprocess
import platform
from datetime import datetime
import time
import logging
import threading
import queue
import concurrent.futures
from colorama import Fore, Back, Style, init
import tqdm
import argparse

init(autoreset=True)

def setup_logging(log_file=None, log_level=logging.INFO):
    """Configure logging with colored console output and optional file output."""
    logger = logging.getLogger("WebScanner")
    logger.setLevel(log_level)
    logger.handlers = []  
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    class ColoredFormatter(logging.Formatter):
        FORMATS = {
            logging.DEBUG: Fore.CYAN + "%(message)s" + Style.RESET_ALL,
            logging.INFO: "%(message)s",
            logging.WARNING: Fore.YELLOW + "%(message)s" + Style.RESET_ALL,
            logging.ERROR: Fore.RED + "%(message)s" + Style.RESET_ALL,
            logging.CRITICAL: Fore.WHITE + Back.RED + "%(message)s" + Style.RESET_ALL
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno)
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)
    
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

def print_banner():
    """Display a stylish banner for the tool."""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  {Fore.WHITE}██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.CYAN}  ║
║  {Fore.WHITE}██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║{Fore.CYAN}  ║
║  {Fore.WHITE}╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║{Fore.CYAN}  ║
║  {Fore.WHITE} ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN}  ║
║                                                               ║
║  {Fore.GREEN}Advanced Website Information Scanner v2.0{Fore.CYAN}                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)

def get_website_info(url, logger, timeout=15):
    """Extract detailed information about the website with progress reporting."""
    logger.info(f"{Fore.BLUE}[+] Analyzing website content and structure...{Style.RESET_ALL}")
    
    info = {"url": url}
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        logger.debug(f"Sending HTTP request to {url} with custom headers")
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=timeout)
        response_time = time.time() - start_time
        
        logger.debug(f"Received response in {response_time:.2f} seconds")
        
        if response.status_code == 200:
            logger.info(f"{Fore.GREEN}[✓] Successfully retrieved website content (Status: 200 OK){Style.RESET_ALL}")
            logger.debug(f"Response size: {len(response.content)} bytes")
            
            logger.debug("Parsing HTML content with BeautifulSoup")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            stages = [
                "Extracting metadata",
                "Analyzing page structure", 
                "Counting page elements",
                "Processing response headers",
                "Checking security headers"
            ]
            
            logger.debug("Starting detailed content analysis")
            for stage in tqdm.tqdm(stages, desc="Content Analysis", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
                time.sleep(0.2) 
                tqdm.tqdm.write(f"  {Fore.CYAN}→ {stage}...{Style.RESET_ALL}")
            
            title = soup.title.string if soup.title else "No title found"
            meta_description = soup.find("meta", attrs={"name": "description"})
            if meta_description and meta_description.get("content"):
                description = meta_description["content"]
            else:
                description = "No description found"
            
            all_links = soup.find_all("a")
            all_images = soup.find_all("img")
            all_scripts = soup.find_all("script")
            all_stylesheets = soup.find_all("link", rel="stylesheet")
            all_forms = soup.find_all("form")
            all_inputs = soup.find_all("input")
            all_iframes = soup.find_all("iframe")
            
            external_links = []
            site_domain = urlparse(url).netloc
            for link in all_links:
                href = link.get('href')
                if href and href.startswith(('http', 'https')) and site_domain not in href:
                    external_links.append(href)
            
            server_info = response.headers.get('Server', 'Not disclosed')
            
            security_headers = {
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Not set"),
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Not set"),
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Not set"),
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Not set"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Not set"),
                "Referrer-Policy": response.headers.get("Referrer-Policy", "Not set")
            }
            
            technologies = []
            
            tech_indicators = {
                "WordPress": ["wp-content", "wp-includes"],
                "Joomla": ["joomla", "com_content"],
                "Drupal": ["drupal", "sites/all"],
                "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                "jQuery": ["jquery.min.js", "jquery"],
                "React": ["react.min.js", "react-dom"],
                "Angular": ["angular.min.js", "ng-app"],
                "Vue.js": ["vue.min.js", "v-app"],
                "Google Analytics": ["google-analytics.com", "gtag"],
                "Font Awesome": ["font-awesome", "fa-"],
                "CloudFlare": ["cloudflare", "__cfduid"]
            }
            
            page_text = response.text.lower()
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in page_text:
                        technologies.append(tech)
                        break
            
            if server_info and server_info != "Not disclosed":
                for tech in ["Apache", "nginx", "IIS", "LiteSpeed", "cloudflare"]:
                    if tech.lower() in server_info.lower():
                        technologies.append(tech)
            
            info.update({
                "title": title,
                "meta_description": description,
                "headings": {
                    "h1": [h.text.strip() for h in soup.find_all("h1")],
                    "h2": [h.text.strip() for h in soup.find_all("h2")][:5],
                    "h3": [h.text.strip() for h in soup.find_all("h3")][:5]
                },
                "page_elements": {
                    "links": len(all_links),
                    "images": len(all_images),
                    "scripts": len(all_scripts),
                    "stylesheets": len(all_stylesheets),
                    "forms": len(all_forms),
                    "inputs": len(all_inputs),
                    "iframes": len(all_iframes)
                },
                "external_links_count": len(external_links),
                "external_links_sample": external_links[:5],
                "server": server_info,
                "headers": dict(response.headers),
                "security_headers": security_headers,
                "cookies": dict(response.cookies),
                "content_type": response.headers.get('Content-Type', 'Unknown'),
                "response_time": response_time,
                "detected_technologies": list(set(technologies))
            })
            
            logger.info(f"{Fore.GREEN}[✓] Website analysis completed successfully{Style.RESET_ALL}")
            logger.info(f"    {Fore.WHITE}Title: {title}{Style.RESET_ALL}")
            logger.info(f"    {Fore.WHITE}Server: {server_info}{Style.RESET_ALL}")
            logger.info(f"    {Fore.WHITE}Response Time: {response_time:.2f} seconds{Style.RESET_ALL}")
            
            return info
        else:
            error_msg = f"Failed to fetch website info, status code: {response.status_code}"
            logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
            return {"error": error_msg}
            
    except requests.exceptions.Timeout:
        error_msg = f"Request timed out after {timeout} seconds"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except requests.exceptions.TooManyRedirects:
        error_msg = "Too many redirects"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except requests.exceptions.ConnectionError:
        error_msg = "Connection error - failed to connect to the server"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"Error fetching website info: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}

def get_domain_info(domain, logger):
    """Get WHOIS and DNS information for a domain with detailed logging."""
    logger.info(f"{Fore.BLUE}[+] Retrieving domain information...{Style.RESET_ALL}")
    
    domain_info = {
        "domain": domain,
        "whois": {},
        "dns": {}
    }
    
    logger.debug(f"Fetching WHOIS data for {domain}")
    try:
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
            
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None
            
        creation_str = str(creation_date) if creation_date else "Unknown"
        expiration_str = str(expiration_date) if expiration_date else "Unknown"
        
        domain_age = None
        if creation_date:
            try:
                current_date = datetime.now()
                if isinstance(creation_date, datetime):
                    domain_age = (current_date - creation_date).days
            except:
                pass
                
        domain_info["whois"] = {
            "registrar": w.registrar,
            "creation_date": creation_str,
            "expiration_date": expiration_str,
            "domain_age_days": domain_age,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "registrant": w.registrant,
            "registrant_country": getattr(w, "registrant_country", None)
        }
        
        logger.info(f"{Fore.GREEN}[✓] WHOIS information retrieved successfully{Style.RESET_ALL}")
        if domain_age:
            logger.info(f"    {Fore.WHITE}Domain Age: {domain_age} days{Style.RESET_ALL}")
        if w.registrar:
            logger.info(f"    {Fore.WHITE}Registrar: {w.registrar}{Style.RESET_ALL}")
        
    except Exception as e:
        error_msg = f"Error retrieving WHOIS data: {str(e)}"
        logger.warning(f"{Fore.YELLOW}[!] {error_msg}{Style.RESET_ALL}")
        domain_info["whois"] = {"error": error_msg}
    
    logger.debug(f"Querying DNS records for {domain}")
    try:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']
        
        for record_type in tqdm.tqdm(record_types, desc="DNS Records", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
            try:
                logger.debug(f"Querying {record_type} records...")
                answers = dns.resolver.resolve(domain, record_type)
                domain_info["dns"][record_type] = [str(answer) for answer in answers]
                tqdm.tqdm.write(f"  {Fore.CYAN}→ Found {len(domain_info['dns'][record_type])} {record_type} record(s){Style.RESET_ALL}")
            except dns.resolver.NoAnswer:
                domain_info["dns"][record_type] = []
                tqdm.tqdm.write(f"  {Fore.YELLOW}→ No {record_type} records found{Style.RESET_ALL}")
            except dns.resolver.NXDOMAIN:
                domain_info["dns"]["error"] = "Domain does not exist"
                tqdm.tqdm.write(f"  {Fore.RED}→ Domain does not exist (NXDOMAIN){Style.RESET_ALL}")
                break
            except Exception as e:
                domain_info["dns"][record_type] = {"error": str(e)}
                tqdm.tqdm.write(f"  {Fore.RED}→ Error querying {record_type} records: {str(e)}{Style.RESET_ALL}")
        
        logger.info(f"{Fore.GREEN}[✓] DNS information retrieved successfully{Style.RESET_ALL}")
        
    except Exception as e:
        error_msg = f"Error retrieving DNS data: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        domain_info["dns"] = {"error": error_msg}
    
    return domain_info

def scan_port(host, port, timeout=1.5, results_queue=None):
    """Scan a single port and return the result."""
    result = {
        "port": port,
        "status": "closed",
        "service": "unknown",
        "details": {}
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        connection_result = sock.connect_ex((host, port))
        scan_time = time.time() - start_time
        
        if connection_result == 0:
            result["status"] = "open"
            result["scan_time"] = f"{scan_time:.3f}s"
            
            try:
                service = socket.getservbyport(port) if port < 1024 else "unknown"
                result["service"] = service
            except:
                pass
                
            if port in [80, 443, 8080, 8443]:
                try:
                    protocol = "https" if port in [443, 8443] else "http"
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                    }
                    response = requests.head(f"{protocol}://{host}:{port}", timeout=3, headers=headers)
                    result["details"]["http_status"] = response.status_code
                    result["details"]["server"] = response.headers.get("Server", "Not disclosed")
                    result["details"]["headers"] = dict(response.headers)
                except:
                    result["details"]["info"] = "Could not retrieve HTTP details"
    
    except socket.timeout:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except:
            pass
    
    if results_queue:
        results_queue.put(result)
    return result

def scan_common_ports(host, logger, ports=None, max_workers=10):
    """Scan for open ports on the host using multithreading."""
    logger.info(f"{Fore.BLUE}[+] Scanning common ports on {host}...{Style.RESET_ALL}")
    
    if ports is None:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139,
            143, 161, 443, 445, 465, 587, 993, 995, 1433, 1521,
            3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 9000
        ]
    
    results = {}
    open_ports = []
    
    results_queue = queue.Queue()
    
    logger.debug(f"Starting port scan with {max_workers} threads")
    
    with tqdm.tqdm(total=len(ports), desc="Port Scanning", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_port, host, port, 1.5, results_queue): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    future.result()
                    
                    while not results_queue.empty():
                        result = results_queue.get()
                        port_num = result["port"]
                        
                        results[port_num] = result
                        
                        if result["status"] == "open":
                            open_ports.append(port_num)
                            service = result["service"]
                            tqdm.tqdm.write(f"  {Fore.GREEN}→ Port {port_num}: {Fore.WHITE}OPEN{Fore.GREEN} ({service}){Style.RESET_ALL}")
                        
                except Exception as exc:
                    logger.debug(f"Port {port} scan generated an exception: {exc}")
                
                pbar.update(1)
    
    while not results_queue.empty():
        result = results_queue.get()
        port_num = result["port"]
        results[port_num] = result
        
        if result["status"] == "open" and port_num not in open_ports:
            open_ports.append(port_num)
            service = result["service"]
            logger.info(f"  {Fore.GREEN}→ Port {port_num}: {Fore.WHITE}OPEN{Fore.GREEN} ({service}){Style.RESET_ALL}")
    
    if open_ports:
        logger.info(f"{Fore.GREEN}[✓] Scan complete: Found {len(open_ports)} open ports{Style.RESET_ALL}")
    else:
        logger.info(f"{Fore.YELLOW}[!] Scan complete: No open ports detected{Style.RESET_ALL}")
    
    return results

def get_ssl_info(hostname, logger, port=443):
    """Get detailed SSL certificate information."""
    logger.info(f"{Fore.BLUE}[+] Analyzing SSL/TLS configuration for {hostname}:{port}...{Style.RESET_ALL}")
    
    try:
        context = ssl.create_default_context()
        
        logger.debug(f"Connecting to {hostname}:{port} for SSL analysis")
        with socket.create_connection((hostname, port), timeout=10) as sock:
            logger.debug("Socket connected, wrapping with SSL context")
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                logger.debug("SSL connection established, retrieving certificate")
                
                cipher = ssock.cipher()
                logger.debug(f"Negotiated cipher: {cipher}")
                
                cert = ssock.getpeercert()
                
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                
                format_str = "%b %d %H:%M:%S %Y %Z"
                cert_valid_from = datetime.strptime(not_before, format_str)
                cert_valid_until = datetime.strptime(not_after, format_str)
                
                cert_validity_days = (cert_valid_until - datetime.now()).days
                
                cert_status = "Valid"
                if cert_validity_days < 0:
                    cert_status = "Expired"
                elif cert_validity_days < 30:
                    cert_status = "Expiring soon"
                
                protocol_version = ssl.get_protocol_name(ssock.version())
                
                ssl_info = {
                    "subject": subject,
                    "issuer": issuer,
                    "subject_alt_names": cert.get('subjectAltName', []),
                    "version": cert['version'],
                    "serial_number": cert['serialNumber'],
                    "not_before": not_before,
                    "not_after": not_after,
                    "valid_from": cert_valid_from.strftime("%Y-%m-%d"),
                    "valid_until": cert_valid_until.strftime("%Y-%m-%d"),
                    "validity_days_remaining": cert_validity_days,
                    "status": cert_status,
                    "cipher": {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2]
                    },
                    "protocol": protocol_version,
                    "OCSP": cert.get('OCSP', []),
                    "caIssuers": cert.get('caIssuers', []),
                    "crlDistributionPoints": cert.get('crlDistributionPoints', [])
                }
                
                logger.info(f"{Fore.GREEN}[✓] SSL certificate retrieved successfully{Style.RESET_ALL}")
                logger.info(f"    {Fore.WHITE}Issued to: {subject.get('commonName', 'Unknown')}{Style.RESET_ALL}")
                logger.info(f"    {Fore.WHITE}Issued by: {issuer.get('organizationName', 'Unknown')}{Style.RESET_ALL}")
                logger.info(f"    {Fore.WHITE}Valid until: {cert_valid_until.strftime('%Y-%m-%d')} ({cert_validity_days} days){Style.RESET_ALL}")
                logger.info(f"    {Fore.WHITE}Status: {cert_status}{Style.RESET_ALL}")
                logger.info(f"    {Fore.WHITE}Protocol: {protocol_version}{Style.RESET_ALL}")
                
                return ssl_info
    except ssl.SSLError as e:
        error_msg = f"SSL Error: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except socket.gaierror as e:
        error_msg = f"DNS resolution error: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except socket.timeout:
        error_msg = "Connection timed out"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"Error retrieving SSL information: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}

def traceroute(hostname, logger):
    """Run a traceroute to the hostname with enhanced visualization."""
    logger.info(f"{Fore.BLUE}[+] Performing network traceroute to {hostname}...{Style.RESET_ALL}")
    
    results = {
        "hops": [],
        "raw_output": []
    }
    
    try:
        is_windows = platform.system().lower() == "windows"
        
        if is_windows:
            cmd = ["tracert", "-d", "-w", "1000", hostname]
            logger.debug(f"Running Windows tracert command: {' '.join(cmd)}")
        else:
            cmd = ["traceroute", "-n", "-w", "1", hostname]
            logger.debug(f"Running Unix traceroute command: {' '.join(cmd)}")
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        hop_num = 0
        raw_output = []
        
        for line in iter(process.stdout.readline, ''):
            if not line.strip():
                continue
                
            raw_output.append(line.strip())
            
            if "traceroute to" in line.lower() or "tracing route to" in line.lower():
                continue
                
            if is_windows:
                if line.strip().startswith(tuple("0123456789")):
                    parts = line.strip().split()
                    hop_num = int(parts[0])
                    
                    ips = []
                    times = []
                    
                    for part in parts[1:]:
                        if part == "*":
                            continue
                            
                        if part.replace(".", "").isdigit():
                            ips.append(part)
                        elif "ms" in part:
                            times.append(float(part.replace("ms", "")))
                    
                    if ips:
                        for ip in ips:
                            hop_info = {
                                "hop": hop_num,
                                "ip": ip,
                                "rtt": min(times) if times else None
                            }
                            results["hops"].append(hop_info)
                            
                            if times:
                                rtt_str = f"{min(times):.1f} ms"
                                logger.info(f"  {Fore.GREEN}→ Hop {hop_num}: {Fore.WHITE}{ip}{Fore.GREEN} ({rtt_str}){Style.RESET_ALL}")
                            else:
                                logger.info(f"  {Fore.GREEN}→ Hop {hop_num}: {Fore.WHITE}{ip}{Fore.GREEN} (No timing data){Style.RESET_ALL}")
                    else:
                        hop_info = {
                            "hop": hop_num,
                            "ip": None,
                            "rtt": None
                        }
                        results["hops"].append(hop_info)
                        logger.info(f"  {Fore.YELLOW}→ Hop {hop_num}: * * * Request timed out{Style.RESET_ALL}")
            else:
                if line.strip() and line.strip()[0].isdigit():
                    parts = line.strip().split()
                    hop_num = int(parts[0])
                    
                    if len(parts) >= 2:
                        ip = None
                        rtt = None
                        
                        for i in range(1, len(parts)):
                            if parts[i].count('.') == 3 and parts[i].replace('.', '').isdigit():
                                ip = parts[i]
                            elif parts[i].replace('.', '').isdigit() and i+1 < len(parts) and parts[i+1] == 'ms':
                                rtt = float(parts[i])
                        
                        hop_info = {
                            "hop": hop_num,
                            "ip": ip,
                            "rtt": rtt
                        }
                        results["hops"].append(hop_info)
                        
                        if ip:
                            if rtt:
                                rtt_str = f"{rtt:.1f} ms"
                                logger.info(f"  {Fore.GREEN}→ Hop {hop_num}: {Fore.WHITE}{ip}{Fore.GREEN} ({rtt_str}){Style.RESET_ALL}")
                            else:
                                logger.info(f"  {Fore.GREEN}→ Hop {hop_num}: {Fore.WHITE}{ip}{Fore.GREEN} (No timing data){Style.RESET_ALL}")
                        else:
                            logger.info(f"  {Fore.YELLOW}→ Hop {hop_num}: * * * Request timed out{Style.RESET_ALL}")
        
        process.wait()
        results["raw_output"] = raw_output
        
        stderr = process.stderr.read()
        if stderr:
            logger.debug(f"Traceroute stderr: {stderr}")
            
        logger.info(f"{Fore.GREEN}[✓] Traceroute completed successfully with {len(results['hops'])} hops{Style.RESET_ALL}")
        
        return results
        
    except subprocess.SubprocessError as e:
        error_msg = f"Error running traceroute command: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"Error performing traceroute: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}

def check_security_vulnerabilities(url, logger):
    """Check for basic security vulnerabilities by examining HTTP responses."""
    logger.info(f"{Fore.BLUE}[+] Checking common security issues for {url}...{Style.RESET_ALL}")
    
    results = {
        "vulnerabilities": [],
        "warnings": [],
        "passed_tests": []
    }
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        }
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        security_checks = [
            {"name": "HTTPS Availability", "url": url.replace("http:", "https:", 1) if url.startswith("http:") else url},
            {"name": "HTTP to HTTPS Redirect", "url": url.replace("https:", "http:", 1) if url.startswith("https:") else url},
            {"name": "Server Information Disclosure", "url": url},
            {"name": "Robots.txt Check", "url": f"{base_url}/robots.txt"},
            {"name": "Directory Listing", "url": f"{base_url}/images/"},
            {"name": "Admin Panel Exposure", "url": f"{base_url}/admin/"},
            {"name": "PHP Info Exposure", "url": f"{base_url}/phpinfo.php"},
            {"name": "Error Page Information Disclosure", "url": f"{base_url}/nonexistentpage123"}
        ]
        
        logger.debug(f"Running {len(security_checks)} security checks")
        
        for check in tqdm.tqdm(security_checks, desc="Security Checks", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
            try:
                check_name = check["name"]
                check_url = check["url"]
                
                logger.debug(f"Running '{check_name}' check for {check_url}")
                
                response = requests.get(check_url, headers=headers, timeout=10, allow_redirects=True)
                
                if check_name == "HTTPS Availability":
                    if check_url.startswith("https:") and response.status_code < 400:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "HTTPS is properly configured"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ HTTPS is properly configured{Style.RESET_ALL}")
                    elif check_url.startswith("https:"):
                        results["vulnerabilities"].append({
                            "name": check_name,
                            "details": "HTTPS is not properly configured",
                            "status_code": response.status_code
                        })
                        tqdm.tqdm.write(f"  {Fore.RED}✗ HTTPS is not properly configured (Status: {response.status_code}){Style.RESET_ALL}")
                
                elif check_name == "HTTP to HTTPS Redirect":
                    if check_url.startswith("http:") and response.url.startswith("https:"):
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "HTTP properly redirects to HTTPS"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ HTTP properly redirects to HTTPS{Style.RESET_ALL}")
                    elif check_url.startswith("http:") and not response.url.startswith("https:"):
                        results["vulnerabilities"].append({
                            "name": check_name,
                            "details": "HTTP does not redirect to HTTPS"
                        })
                        tqdm.tqdm.write(f"  {Fore.RED}✗ HTTP does not redirect to HTTPS{Style.RESET_ALL}")
                
                elif check_name == "Server Information Disclosure":
                    server = response.headers.get("Server", "")
                    if server and any(tech in server for tech in ["Apache", "nginx", "IIS", "version"]):
                        results["warnings"].append({
                            "name": check_name,
                            "details": f"Server header reveals information: {server}"
                        })
                        tqdm.tqdm.write(f"  {Fore.YELLOW}! Server header reveals technology information: {server}{Style.RESET_ALL}")
                    else:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "Server header does not reveal sensitive information"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ Server header does not reveal sensitive information{Style.RESET_ALL}")
                
                elif check_name == "Robots.txt Check":
                    if response.status_code == 200 and "Disallow:" in response.text:
                        sensitive_paths = []
                        for line in response.text.splitlines():
                            if "Disallow:" in line and any(term in line.lower() for term in ["admin", "login", "user", "password", "config", "backup"]):
                                sensitive_paths.append(line.strip())
                        
                        if sensitive_paths:
                            results["warnings"].append({
                                "name": check_name,
                                "details": f"Robots.txt reveals sensitive paths: {', '.join(sensitive_paths[:3])}"
                            })
                            tqdm.tqdm.write(f"  {Fore.YELLOW}! Robots.txt reveals potentially sensitive paths{Style.RESET_ALL}")
                        else:
                            results["passed_tests"].append({
                                "name": check_name,
                                "details": "Robots.txt exists but does not reveal sensitive paths"
                            })
                            tqdm.tqdm.write(f"  {Fore.GREEN}✓ Robots.txt exists but does not reveal sensitive paths{Style.RESET_ALL}")
                
                elif check_name == "Directory Listing":
                    if response.status_code == 200 and "<title>Index of" in response.text:
                        results["vulnerabilities"].append({
                            "name": check_name,
                            "details": "Directory listing is enabled"
                        })
                        tqdm.tqdm.write(f"  {Fore.RED}✗ Directory listing is enabled{Style.RESET_ALL}")
                    else:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "Directory listing is disabled or not found"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ Directory listing is disabled or not found{Style.RESET_ALL}")
                
                elif check_name == "Admin Panel Exposure":
                    if response.status_code < 400:
                        results["warnings"].append({
                            "name": check_name,
                            "details": "Admin panel might be accessible"
                        })
                        tqdm.tqdm.write(f"  {Fore.YELLOW}! Admin panel might be accessible (Status: {response.status_code}){Style.RESET_ALL}")
                    else:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "Admin panel not found or protected"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ Admin panel not found or protected{Style.RESET_ALL}")
                
                elif check_name == "PHP Info Exposure":
                    if response.status_code == 200 and ("phpinfo()" in response.text or "PHP Version" in response.text):
                        results["vulnerabilities"].append({
                            "name": check_name,
                            "details": "PHPInfo page is exposed"
                        })
                        tqdm.tqdm.write(f"  {Fore.RED}✗ PHPInfo page is exposed{Style.RESET_ALL}")
                    else:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "PHPInfo page not found or protected"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ PHPInfo page not found or protected{Style.RESET_ALL}")
                
                elif check_name == "Error Page Information Disclosure":
                    if response.status_code >= 400 and any(term in response.text for term in ["fatal error", "stack trace", "syntax error", "exception", "SQL syntax"]):
                        results["vulnerabilities"].append({
                            "name": check_name,
                            "details": "Error page reveals sensitive information"
                        })
                        tqdm.tqdm.write(f"  {Fore.RED}✗ Error page reveals sensitive information{Style.RESET_ALL}")
                    else:
                        results["passed_tests"].append({
                            "name": check_name,
                            "details": "Error page does not reveal sensitive information"
                        })
                        tqdm.tqdm.write(f"  {Fore.GREEN}✓ Error page does not reveal sensitive information{Style.RESET_ALL}")
                
            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                logger.debug(f"Error in security check '{check_name}': {str(e)}")
        
        if results["vulnerabilities"]:
            logger.info(f"{Fore.RED}[!] Found {len(results['vulnerabilities'])} potential security vulnerabilities{Style.RESET_ALL}")
        elif results["warnings"]:
            logger.info(f"{Fore.YELLOW}[!] Found {len(results['warnings'])} security warnings{Style.RESET_ALL}")
        else:
            logger.info(f"{Fore.GREEN}[✓] No obvious security issues detected{Style.RESET_ALL}")
        
        return results
        
    except Exception as e:
        error_msg = f"Error checking security vulnerabilities: {str(e)}"
        logger.error(f"{Fore.RED}[✗] {error_msg}{Style.RESET_ALL}")
        return {"error": error_msg}

def generate_report(all_results, output_format="json", output_file=None):
    """Generate a comprehensive report from all scan results."""
    if output_format.lower() == "json":
        report = json.dumps(all_results, indent=4, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            return f"Report saved to {output_file}"
        else:
            return report
    else:
        return "Unsupported format"

def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(description='Advanced Website Information Scanner')
    parser.add_argument('url', help='Target URL or domain to scan')
    parser.add_argument('--output', '-o', help='Output file for the report')
    parser.add_argument('--format', '-f', default='json', choices=['json'], help='Output format (default: json)')
    parser.add_argument('--port-scan', '-p', action='store_true', help='Enable port scanning')
    parser.add_argument('--security-check', '-s', action='store_true', help='Enable security vulnerability checks')
    parser.add_argument('--traceroute', '-t', action='store_true', help='Enable network traceroute')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--log-file', '-l', help='Log file path')
    parser.add_argument('--all', '-a', action='store_true', help='Enable all scanning features')
    parser.add_argument('--timeout', default=15, type=int, help='Request timeout in seconds (default: 15)')
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(args.log_file, log_level)
    
    print_banner()
    
    url = args.url
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    logger.info(f"\n{Fore.CYAN}[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}[*] Target: {url}{Style.RESET_ALL}")
    
    all_results = {
        "scan_metadata": {
            "target": url,
            "domain": domain,
            "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "scanner_version": "2.0"
        }
    }
    
    try:
        logger.info(f"{Fore.CYAN}=" * 70)
        logger.info(f"WEBSITE INFORMATION SCAN")
        logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
        
        website_info = get_website_info(url, logger, timeout=args.timeout)
        all_results["website_info"] = website_info
        
        logger.info(f"{Fore.CYAN}=" * 70)
        logger.info(f"DOMAIN INFORMATION SCAN")
        logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
        
        domain_info = get_domain_info(domain, logger)
        all_results["domain_info"] = domain_info
        
        if url.startswith('https://'):
            logger.info(f"{Fore.CYAN}=" * 70)
            logger.info(f"SSL/TLS CERTIFICATE SCAN")
            logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
            
            ssl_info = get_ssl_info(domain, logger)
            all_results["ssl_info"] = ssl_info
        
        if args.port_scan or args.all:
            logger.info(f"{Fore.CYAN}=" * 70)
            logger.info(f"PORT SCAN")
            logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
            
            port_scan_results = scan_common_ports(domain, logger)
            all_results["port_scan"] = port_scan_results
        
        if args.security_check or args.all:
            logger.info(f"{Fore.CYAN}=" * 70)
            logger.info(f"SECURITY VULNERABILITY SCAN")
            logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
            
            security_check_results = check_security_vulnerabilities(url, logger)
            all_results["security_check"] = security_check_results
        
        if args.traceroute or args.all:
            logger.info(f"{Fore.CYAN}=" * 70)
            logger.info(f"NETWORK TRACEROUTE")
            logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
            
            traceroute_results = traceroute(domain, logger)
            all_results["traceroute"] = traceroute_results
        
        logger.info(f"{Fore.CYAN}=" * 70)
        logger.info(f"SCAN COMPLETED")
        logger.info(f"=" * 70 + f"{Style.RESET_ALL}\n")
        
        if args.output:
            report_result = generate_report(all_results, args.format, args.output)
            logger.info(f"{Fore.GREEN}[✓] {report_result}{Style.RESET_ALL}")
        else:
            logger.info(f"{Fore.YELLOW}[!] No output file specified. Use --output to save results.{Style.RESET_ALL}")
            
        logger.info(f"\n{Fore.CYAN}[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        logger.info(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n{Fore.RED}[✗] An error occurred during scanning: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()

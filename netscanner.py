import nmap
import requests
from bs4 import BeautifulSoup

def scan_network(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV')
    result = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            result.append({
                'port': port,
                'name': nm[ip][proto][port]['name'],
                'version': nm[ip][proto][port]['version']
            })
    return result

def search_exploitdb(service, version):
    query = f"{service} {version}"
    url = f"https://www.exploit-db.com/search?cve={query}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for link in soup.find_all('a', class_='search-result-title'):
        results.append(link['href'])
    return results

def search_google_hacking_db(service, version):
    query = f"{service} {version} site:exploit-db.com"
    url = f"https://www.google.com/search?q={query}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for item in soup.find_all('h3'):
        link = item.find_parent('a')['href']
        results.append(link)
    return results

if __name__ == "__main__":
    ip = '192.168.1.1'  # Change this to your target IP
    scan_results = scan_network(ip)
    for service in scan_results:
        print(f"Port: {service['port']}, Name: {service['name']}, Version: {service['version']}")
        vulnerabilities_exploitdb = search_exploitdb(service['name'], service['version'])
        vulnerabilities_ghdb = search_google_hacking_db(service['name'], service['version'])
        print("Vulnerabilities from ExploitDB:")
        for v in vulnerabilities_exploitdb:
            print(f"  {v}")
        print("Vulnerabilities from Google Hacking Database:")
        for v in vulnerabilities_ghdb:
            print(f"  {v}")

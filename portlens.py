import sys
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import textwrap
import random

#Author: Vahe Demirkhanyan

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 8.0.0; Mobile; rv:61.0) Gecko/61.0 Firefox/61.0",
    "Mozilla/5.0 (iPad; CPU OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0"
]

def get_port_info(port_number):
    url = f"https://www.speedguide.net/port.php?port={port_number}"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        response = requests.get(url, headers=headers, timeout=10)  # Set a timeout limit of 10 seconds
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            port_table = soup.find('table', class_='port')
            if port_table:
                services = []
                threats = []
                detailed_info = []
                first_row = True
                for row in port_table.find_all('tr')[1:]:
                    try:
                        cols = [td.text.strip() for td in row.find_all('td')]
                        service_info = dict(zip(['Port', 'Protocol', 'Service', 'Details', 'Source'], cols))

                        if first_row and service_info['Source'] == 'SG':  # Check if it's the first row and source is 'SG'
                           detailed_info.append(service_info)
                           first_row = False  # Reset the flag after the first row is processed
                        else:
                           category = categorize_entry(service_info)
                           if category == 'Threats and Trojans':
                               threats.append(service_info)
                           else:
                               services.append(service_info)
                    except Exception as e:
                        print(f"Failed to parse row due to: {str(e)}")
                return services, threats, detailed_info

            else:
                return "No detailed information found for this port."
        else:
            return "Failed to retrieve information."
    except requests.exceptions.Timeout:
        return "Request timed out."
    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}"

def print_details(title, items, is_detailed=False):
    print(f"\n{Fore.YELLOW + Style.BRIGHT}{title.upper()}:")
    if items:
        for item in items:
            if is_detailed:
                # Special formatting for detailed information
                print(f"{Fore.MAGENTA}  Port: {item['Port']} | {Fore.GREEN}Protocol: {item['Protocol']} | {Fore.GREEN + Style.BRIGHT}Service: {item['Service']} | {Fore.BLUE}Source: {item['Source']}")
                details_wrapped = textwrap.fill(item['Details'], width=120, subsequent_indent='           ')
            else:
                print(f"{Fore.CYAN}  Port: {item['Port']} | {Fore.GREEN}Protocol: {item['Protocol']} | {Fore.GREEN + Style.BRIGHT}Service: {item['Service']} | {Fore.BLUE}Source: {item['Source']}")
                details_wrapped = textwrap.fill(item['Details'], width=100, subsequent_indent='           ')
            print(f"{Fore.WHITE}  Details: {details_wrapped}")
    else:
        print(f"{Fore.RED}  No data available.")

def categorize_entry(service_info):
    threats_keywords = ['[trojan]', 'trojan', 'threat']
    if "Trojans" in service_info['Source'] or any(keyword in service_info['Details'] for keyword in threats_keywords) or any(keyword in service_info['Service'] for keyword in threats_keywords):
        return 'Threats and Trojans'
    else:
        return 'Services and Programs'

def main():
    if len(sys.argv) > 1:
        ports = sys.argv[1].split(',')
        for port in ports:
            try:
                port = int(port.strip())
                services, threats, detailed_info = get_port_info(port)
                if services or threats or detailed_info:
                    print(f"\n{Fore.GREEN + Style.BRIGHT}{'=' * 20} Information for Port {port} {'=' * 20}")
                    print_details("General Information", detailed_info, is_detailed=True)
                    print_details("Services and Programs", services)
                    print_details("Threats and Trojans", threats)
                    print(f"{Fore.RED + Style.BRIGHT}{'-' * 80}") 
                else:
                    print("No information found.")
            except ValueError:
                print(f"Error: Invalid port number '{port}'")
    else:
        print("Usage: python script.py <port1,port2,...>")

if __name__ == "__main__":
    main()

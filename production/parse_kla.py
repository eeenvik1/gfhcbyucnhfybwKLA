#! /usr/bin/python

import requests
from bs4 import BeautifulSoup
import json
import urllib3
import re
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_kla(KLA):  #  Теперь точно работает классно
    cve_id = []
    url = 'https://threats.kaspersky.com/ru/vulnerability/' + KLA
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'lxml')
    items = soup.find_all('a', class_='gtm_vulnerabilities_cve')
    for i in items:
        buff = i.get_text()
        regex = re.search(r'CVE-\d{4}-\d{4,6}', buff)
        if(regex != None):
            cve_id.append(buff)
    return cve_id

def cve_replace(cve): # Допилить if на CVSSv3 и CVSSv2, а так работает классно
    API = 'API'
    url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve + API
    response = requests.get(url, verify=False)
    parse_text = response.json()
    description = parse_text['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
    sol = parse_text['result']['CVE_Items'][0]['cve']['references']['reference_data']
    for n, solutions in enumerate(sol, start = 0):
        try:
            if(sol[n]['tags'][n] == 'Patch'):
                solution = 'Официальный патч: ' + solutions['url']
        except:
            solution = 'Подробная информация: ' + solutions['url']
    vector = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString']
    score = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    print(f'{cve}', file = fout)
    print(f'Описание:\n{description}', file = fout)
    print(f'{solution}', file = fout)
    print(f'CVSSv3 Score: {score}', file = fout)
    print(f'CVSSv3 vector: {vector}\n', file = fout)

def read2list_kla(file):
    kla_line = []
    with open(file, 'r', encoding="utf-8") as file:
        for i in file:
            buff = i.strip()
            regex_kla = re.findall(r'KLA\d{4,7}', buff)
            if (regex_kla != None):
                kla_line.append(regex_kla)
    return kla_line
    
def read2list_ip(file):
    ip_line = []
    with open(file, 'r', encoding="utf-8") as file:
        for i in file:
            buff = i.strip()
            regex_ip = re.findall(r'\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}', buff)
            if (regex_ip != None):
                ip_line.append(regex_ip)
    return ip_line


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Error!\nUsage: python3 %s " % sys.argv[0] + "file.txt")
        exit()
    try:
        file_in = str(sys.argv[1])
        fout = open('output.txt', 'w')
        kla_list = read2list_kla(file_in)
        ip_list = read2list_ip(file_in)
        for n,i in enumerate(kla_list, start = 0):
    	    list_to_str_kla = ''.join(kla_list[n])
    	    buff = parse_kla(list_to_str_kla)
    	    for cve in buff:
                list_to_str_ip = ', '.join(ip_list[n])
                print(f'На IP: {list_to_str_ip} присутствует:', file = fout)
                cve_replace(cve)
        print(f'Done!')
        fout.close()
    except:
        print("Error!\nNo such file: %s " % sys.argv[1])
        fout.close()


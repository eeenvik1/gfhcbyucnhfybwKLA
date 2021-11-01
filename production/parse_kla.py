#! /usr/bin/python

import requests
from bs4 import BeautifulSoup
import urllib3
import re
import sys
import lxml.etree as ET
import csv
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  'http': 'http://proxy:port',
  'https': 'http://proxy:port',
}

def parse_kla(KLA): # Теперь точно работает классно
    cve_id = []
    url = 'https://threats.kaspersky.com/ru/vulnerability/' + KLA
    response = requests.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(response.text, 'lxml')
    items = soup.find_all('a', class_='gtm_vulnerabilities_cve')
    for i in items:
        buff = i.get_text()
        regex = re.search(r'CVE-\d{4}-\d{4,6}', buff)
        if (regex != None):
            cve_id.append(buff)
    return cve_id


def cve_replace(cve, IP, HOSTNAME):  # Допилить if на CVSSv3 и CVSSv2, а так работает классно
    global solution
    global solutions
    API = 'API'
    if (API == 'API'):
        print(f'Ключ API')
        exit()
    url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve + API
    link = 'https://nvd.nist.gov/vuln/detail/' + cve
    response = requests.get(url, verify=False, proxies=proxies)
    parse_text = response.json()
    description = parse_text['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
    sol = parse_text['result']['CVE_Items'][0]['cve']['references']['reference_data']
    for n, solutions in enumerate(sol[0]['tags'], start=0):
        try:
            if (sol[0]["tags"][n] == "Patch"):
                solutions = sol[0]['url']
                solution = 'Официальный патч: ' + solutions
            else:
                solutions = sol[0]['url']
                solution = 'Подробное решение: ' + solutions
        except:
            print('')
    try:
        v3 = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString']
        s3 = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
        vector = v3
        score = s3
    except:
        vector = 'N/A'
        score = 'N/A'

    #Make logs.txt
    print(f'{cve}', file=fout)
    print(f'Описание:\n{description}', file=fout)
    print(f'{solution}', file=fout)
    print(f'CVSSv3 Score: {score}', file=fout)
    print(f'CVSSv3 vector: {vector}\n', file=fout)

    cve3 = str(cve)
    vec = str(vector)
    vector1 = '(' + vec + ')'
    tree = ET.parse("D:\PyCharm_Projects\project_1\/sample.xml") #Path to sample.xml
    root = tree.getroot()
    val = str(IP)
    hostname = str(HOSTNAME)
    for elem in root[2][0][0][0][2]:
        elem.set('id', cve3)

    for elem in root[2]:
        elem.set('ip', val)
        elem.set('fqdn', hostname)
    
    for elem in root[3]:
        elem[0].text = cve3
        elem[1].text = str(description)
        elem[2].text = str(description)
        elem[3].text = str(solution)
        elem[4].text = str(link)
        elem[7].attrib['temp_score'] = str(score)
        elem[7].attrib['base_score'] = str(score)
        elem[7].attrib['temp_score_decomp'] = vector1
        elem[7].attrib['base_score_decomp'] = vector1
        elem.set('id', cve3)

    if not os.path.isdir("result"):
        os.mkdir("result")
    filename = val + '-' + cve3 + '.xml'
    tree.write('D:\PyCharm_Projects\project_1\/result' +'\/'+ val + '-' + cve3 + '.xml') # Path to folder
    print(f'Файл {filename} создан')

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

def read2hostname_list(file):
    hostname_line = []
    with open(file) as f_obj:
        reader = csv.reader(f_obj, delimiter=' ')
        for line in reader:
            buff = line[2]
            if(buff != None):
                hostname_line.append(buff)
    return hostname_line

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Error!\nUsage: python3 %s " % sys.argv[0] + "file.txt")
        exit()

    fout = open('logs.txt', 'w')
    file_in = str(sys.argv[1])
    kla_list = read2list_kla(file_in)
    ip_list = read2list_ip(file_in)
    dlina = len(kla_list)
    hostname_list = read2hostname_list(file_in)
    for n, i in enumerate(kla_list, start=0):
        list_to_str_kla = ''.join(kla_list[n])
        buff = parse_kla(list_to_str_kla)
        print(f'Строка {n+1} из {dlina}')
        for number, cve in enumerate(buff,start=0):
            list_to_str_ip = ', '.join(ip_list[n])
            for IP in ip_list[n]:
                print(f'{IP} ({hostname_list[n]})', file=fout)
                cve_replace(cve, IP, hostname_list[n])
    print(f'Done!')
    fout.close()

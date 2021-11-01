#!/usr/bin/python

import requests
import urllib3
import json
import time
import datetime

PROTOCOL = 'http'
RVISION = '10.10.10.10'
USERNAME = 'user'
PASSWORD = 'pass'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Начало сессии
s = requests.Session()
login = s.post(
    PROTOCOL + '://' + RVISION + '/login',
    data={
        'username': USERNAME,
        'password': PASSWORD
    },
    verify=False
)
loginResult = login.text

# Получение csrf
unixtime = str(time.mktime(datetime.datetime.now().timetuple()))[:-2]
check_csrf = s.get(
    PROTOCOL + '://' + RVISION + '/csrfToken?' + unixtime,
    verify=False
)
csrf = json.loads(check_csrf.text)["_csrf"]

# Фильтры
incidentsFilter = [{
    "property": "from", "operator": "in", "value": ["ksc"]},
    {"property": "status", "operator": "in", "value": ["opened"]
     }]

# Параметры
devicesParams = {
    'page': 1,  # Пагинация, номер страницы
    'start': 0,  # Пагинация, позиция элемента с которого начать поиск
    'limit': 20,  # 99999 - вывод всех строк
    'filters': json.dumps(incidentsFilter)
}

# Запрос на выгрузку
export = s.get(
    PROTOCOL + '://' + RVISION + '/api/v2/am/vulnerabilities/devices',
    params=devicesParams,
    verify=False
)
exportResult = export.json()

# DEBUG
# print(json.dumps(exportResult, indent=2, sort_keys=True, ensure_ascii=False))

fout = open('result_parse_RV.csv', 'w')

for n, key in enumerate(exportResult["data"], start=0):
    KLA_NAME = exportResult["data"][n]["name"]
    IP = exportResult["data"][n]["ifs"]
    HOSTNAME = exportResult["data"][n]["device_name"]
    if(IP != None):
        print(f'{KLA_NAME} {IP[0]["ip"]} {HOSTNAME}', file=fout)

fout.close()

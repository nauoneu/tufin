import requests
from requests.auth import HTTPBasicAuth
import sys
import re
import csv
import json
from pprint import pprint
# disable SSL warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# global vars
host = '192.168.32.99'
user = 'admin'
password = 'tufin123'
headers = {}
debug = False

def http_get(url, headers=headers):
    try:
        r = requests.get(url=url, headers=headers, auth=HTTPBasicAuth(user,password), verify=False)
    except requests.exceptions.RequestException as e:
        print(e, file=sys.stderr)
        return

    if debug:
        print("HTTP GET response:")
        pprint(r)

    return r

def get_json(res):
    try:
        rjson = res.json()
    except UnicodeDecodeError as e:
        print("Cannot decode json data in HTTP response")
        return
    except:
#        e = sys.exc_info()[0]
#        print(e)
        return

    if debug:
        print("HTTP GET response in JSON format:")
        pprint(rjson)

    return rjson

def check_response(res):
    rjson = get_json(res)
    if not rjson:
        return

    status = res.status_code
    if not status:
        print("fail to get status code")
    else:
        if status == 200:
            if debug: print("200 successful request")
            return rjson
        elif status == 400:
            print("400 Invalid request format")
        elif status == 403:
            print("403 Permission denied")
        elif status == 404:
            print("404 None existing resource")
        elif status == 405:
            print("405 Unsupported method")
        elif status == 424:
            print("424 Dependency error")
        elif status == 500:
            print("500 Internal server error")
        else:
            print(status, "Unknown error")

if  __name__ == "__main__":
    if sys.argv[1:4]:
        host, user, password = sys.argv[1:4]
    else:
        print("Please specify host, user and password as command line optinos:")
        print("python tufin.py <host> <user> <password>")
        print("The script is using default values:")
        print(f"host: {host}, user: {user}, password: {password}")

    headers['Accept'] = 'application/json'
    file = input("Input file name : ")
    src = input("Input Source IP (eg. 10.0.0.0:24, 192.168.3.100): ")
#    dst = input("Input Destination IP (eg. 10.0.0.0:24, 172.16.40.1): ")
    service = input("Input Service (eg. tcp:80, facebook, any): ")

    with open(file, newline = "") as f:
        read_dict = csv.DictReader(f, delimiter=",", quotechar='"')
        ks = read_dict.fieldnames
        return_dict = {k: [] for k in ks}

        for row in read_dict:
            for k, v in row.items():
                return_dict[k].append(v)

    i = 0
    print("\nSource : " + str(src))
    print("Destination:        Subnet:             Allowed:")
    print("------------------------------------------------------------")
    for dst in return_dict[ks[1]]:
        dst = dst.replace('/', ':')
        url = f"https://{host}/securetrack/api/topology/path?src={src}&dst={dst}&service={service}"

        if debug:
            print("Requested URL:")
            print(url)

        if not http_get(url):
            print(f"{return_dict[ks[0]][i]:<20}{return_dict[ks[1]][i]:<20}No Response")
            i += 1
            continue

        res = http_get(url)
        check_response(res)
        rdict = get_json(res)

        print(f"{return_dict[ks[0]][i]:<20}{return_dict[ks[1]][i]:<20}{str(rdict['path_calc_results']['traffic_allowed']):<20}\n")
        print("    Permit rules through traffic path:")
        print("    ----------------------------------------------")

        for devinf in rdict['path_calc_results']['device_info']:
            if debug:
                print("Debug Devinf:")
                print(devinf)

            for bindings in devinf['bindings']:
                if debug:
                    print("Debug Bindings:")
                    print(bindings)

                rulecnt = len(bindings['rules'])
                for j in range(rulecnt):
                    rule = bindings['rules'][j]
                    print(f"    Device: {devinf['name']:<12}Action: {rule['action']}")
                    if rule['action'] == "Accept" or rule['action'] == "Allow":
                        print(f"        Rule ID: {rule['ruleIdentifier']}")
                        print(f"        Sources: {rule['sources']}")
                        print(f"        Destinations: {rule['destinations']}")
                        print(f"        Services: {rule['services']}")
                        print("")
                    else:
                        print("")

        i += 1

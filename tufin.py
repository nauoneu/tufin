import requests
from requests.auth import HTTPBasicAuth
import sys
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

def http_post(url, data, headers=headers):
    try:
        r = requests.post(url=url, headers=headers, auth=HTTPBasicAuth(user,password), data=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(e, file=sys.stderr)
        return

    if debug:
        print("HTTP POST response:")
        pprint(r)

    return r

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

def menu():
    print("")
    print("========================================")
    print("1: Get devices")
    print("2: Get specific device")
    print("3: Get all domains")
    print("4: Get domain")
    print("5: Get path for specified traffic")
    print("6: Get path image for specified traffic")
    print("0: quit")
    print("========================================")
    try:
        reqid = int(input("Input : "))
    except:
        reqid = 0
    else:
        pass

    if reqid == 0:
        uri = "quit"
    elif reqid == 1:
        uri = "securetrack/api/devices/"
    elif reqid == 2:
        devid = int(input("Input device ID:"))
        uri = f"securetrack/api/devices/{devid}"
    elif reqid == 3:
        uri = "securetrack/api/domains/"
    elif reqid == 4:
        domid = input("Input domain ID:")
        uri = f"securetrack/api/domains/{domid}"
    elif reqid == 5:
        src = input("Input Source IP (eg. 10.0.0.0:24, 192.168.3.100): ")
        dst = input("Input Destination IP (eg. 10.0.0.0:24, 172.16.40.1): ")
        service = input("Input Service (eg. tcp:80, facebook): ")
        uri = f"securetrack/api/topology/path?src={src}&dst={dst}&service={service}"
    elif reqid == 6:
        src = input("Input Source IP (eg. 10.0.0.0:24, 192.168.3.100): ")
        dst = input("Input Destination IP (eg. 10.0.0.0:24, 172.16.40.1): ")
        service = input("Input Service (eg. tcp:80, facebook): ")
        uri = f"securetrack/api/topology/path_image?src={src}&dst={dst}&service={service}"
    else:
        reqid = 0
        uri = ""

    return uri, reqid

def apicall(uri, reqid):
    headers['Accept'] = 'application/json'
    url = f"https://{host}/{uri}"
    print(url)
    res = http_get(url)
    if not check_response(res):
        return
    rdict = get_json(res)

    if reqid == 1:
        total = int(rdict['devices']['total'])
        print(total)
        blank = ""
        for i in range(total):
            try:
                rdict['devices']['device'][i]['name']
            except:
                try:
                    rdict['devices']['device'][i]['ip']
                except:
                    print(f"{rdict['devices']['device'][i]['id']:<5} : {blank: >30} : {blank: >20}")
                else:
                    print(f"{rdict['devices']['device'][i]['id']:<5} : {blank: >30} : {rdict['devices']['device'][i]['ip']:<20}")
            else:
                try:
                    rdict['devices']['device'][i]['ip']
                except:
                    print(f"{rdict['devices']['device'][i]['id']:<5} : {rdict['devices']['device'][i]['name']:<30} : {blank: >20}")
                else:
                    print(f"{rdict['devices']['device'][i]['id']:<5} : {rdict['devices']['device'][i]['name']:<30} : {rdict['devices']['device'][i]['ip']:<20}")
    elif reqid == 2:
        pprint(res.json())
    elif reqid == 3:
        pprint(res.json())
    elif reqid == 4:
        pprint(res.json())
    elif reqid == 5:
        print("Traffic Allowed : " + str(rdict['path_calc_results']['traffic_allowed']))
#        pprint(res.json())

#        print(f"{return_dict[ks[0]][i]:<20}{return_dict[ks[1]][i]:<20}{str(rdict['path_calc_results']['traffic_allowed']):<20}\n")
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

    elif reqid == 6:
        pass

if  __name__ == "__main__":
    if sys.argv[1:4]:
        host, user, password = sys.argv[1:4]
    else:
        print("Please specify host, user and password as command line optinos:")
        print("python tufin.py <host> <user> <password>")
        print("The script is using default values:")
        print(f"host: {host}, user: {user}, password: {password}")

    while True:
        uri, reqid = menu()
        if reqid == 0:
            print("quit the menu...")
            break
        else:
            apicall(uri, reqid)


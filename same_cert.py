from bs4 import BeautifulSoup
from pprint import pprint
import re 
import textwrap
import argparse

def parse(file):
    lines= file.read()
    xml_parsed_content=BeautifulSoup(lines, features="lxml")
    list_of_hosts_and_certs = []
    for hostik in xml_parsed_content.nmaprun.find_all("host"):
        for portik in hostik.find_all("port"):
            for scriptik in portik.find_all("script"):
                sha1_cert_hash = re.search('<elem key=\"sha1\">([a-f0-9]{40})</elem>', str(scriptik))
                if sha1_cert_hash !=None:
                    dictionary ={}
                    dictionary["host"] = hostik.find("hostname")["name"]
                    dictionary["addr"] = hostik.address["addr"] +":"+ portik["portid"]
                    dictionary["sha1"] = sha1_cert_hash.group(1)
                    list_of_hosts_and_certs.append(dictionary)
    return list_of_hosts_and_certs

def output(arr, scope):
    answ_arr=[]
    for test in arr:
        if (test["host"] in scope) or scope==[]:
            anws_dict = {}
            anws_dict["host"] = test["host"]
            anws_dict["addr"] = test["addr"]
            anws_dict["same_cert"] = []
            for dicts in arr:
                if test["sha1"] == dicts["sha1"]:
                    if scope==[]:
                        anws_dict["same_cert"].append({"host":dicts["host"],"addr":dicts["addr"]})
                    else:
                        if dicts["host"] not in scope:
                            anws_dict["same_cert"].append({"host":dicts["host"],"addr":dicts["addr"]})
            if anws_dict["same_cert"]!=[]:
                answ_arr.append(anws_dict)
    return answ_arr

parser = argparse.ArgumentParser(description='Scope certs finder v0.1', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent("""
Example usage:

python3 same_cert.py -i nmap.xml
or
python3 same_cert.py -i nmap.xml -f scope.txt
or 
python3 same_cert.py -i nmap.xml -s google.com yandex.ru pornhub.com
"""))
parser.add_argument('-s', '--scope', action="store", dest="scope", nargs='+', default=[],  help="Scope domains. Possible valueas are: google.com yandex.ru. Default empty. If not passed, then you will have all domains from nmap")
parser.add_argument('-f' '--scope-file', dest="scope_file", type=argparse.FileType('r', encoding='UTF-8'), help="Scope domains. Same as --scope, but in file. One domain per line. Default empty. If not passed, then you will have all domains from nmap")
parser.add_argument('-i' '--input-file', dest="file", type=argparse.FileType('r', encoding='UTF-8'), required=True, help="Nmap scan in XML file. Scan command example: nmap -sC -p- --resolve-all -iL domains.txt -oX output")
args = parser.parse_args()
if args.scope_file != None:
    scope = args.scope_file.read().splitlines()
else:
    scope = args.scope
list_of_hosts_and_certs = parse(args.file)
pprint(output(list_of_hosts_and_certs, scope))

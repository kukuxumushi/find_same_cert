This script parses nmap XML output in order to find reusage of SSL\TLS certs.

usage: same_cert.py [-h] [-s SCOPE [SCOPE ...]] [-f--scope-file SCOPE_FILE] -i--input-file FILE

Scope certs finder v0.1

optional arguments:
  -h, --help            show this help message and exit
  -s SCOPE [SCOPE ...], --scope SCOPE [SCOPE ...]
                        Scope domains. Possible valueas are: google.com yandex.ru. Default empty. If not passed, then you will have all domains from nmap
  -f--scope-file SCOPE_FILE
                        Scope domains. Same as --scope, but in file. One domain per line. Default empty. If not passed, then you will have all domains from nmap
  -i--input-file FILE   Nmap scan in XML file. Scan command example: nmap -sC -p- -iL domains.txt -oX output

Example usage:
python3 same_cert.py -i nmap.xml

or

python3 same_cert.py -i nmap.xml -f scope.txt

or

python3 same_cert.py -i nmap.xml -s google.com yandex.ru pornhub.com
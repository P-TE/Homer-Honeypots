#   Homer 
<p align="center">
<img src="docs/images/logo.png" width="250">
</p>


Homer est un projet permettant le déploiement automatisé d'Honeypots, à travers une interface graphique.

Les honeypots disponibles à ce jour sont :
* SSH
* FTP 
* Agent Windows

## Installation

### Création d'une VM HomerAgent

_Cette VM à pour but d'accueillir un Agent Honeypot (ssh ou ftp)_

(Installation sur debian 8 netinstall)

* Prérequis : 
 ```bash
 $ apt install ansible openssh-server sudo
 ```
* Création d'un utilisateur ansible : 
 ```bash
 $ adduser ansible
 ```
* Ajout de l'utilisateur ansible au sudoers sans password : 
```bash
$ sudo visudo
``` 
et ajouter à la fin : 
``` bash
ansible ALL=(ALL) NOPASSWD: ALL
```


### Déploiement de HomerServer

* Prérequis : [Docker](https://docs.docker.com/install/)
* Docker : 
```bash
$ docker build . -t homer/server:0.1
$ docker run -d -p 5000:5000 --name homerserver homer/server:0.1
```

* L'IHM est alors disponible sur http://\<ip_locale\>:5000/<br> (:warning: ne pas prendre 127.0.0.1)

* Ajout de la clé ssh du HomerAgent :
```bash
$ docker exec -it homerserver /bin/sh
$ ssh-copy-id ansible@ip_agent
```

## Déploiement d'un honeypot

Retrouvez toutes les informations du déploiement sur le [wiki](https://github.com/P-TE/Homer-Honeypots/wiki/2.-D%C3%A9ploiement-d'un-honeypot).


## Architecture

Voici un exemple d'architecture d'un déploiement d'Homer : 
<center><img src="docs/images/architecture_homer.png"></center>


## Auteurs

Blablach [@blablachet](https://twitter.com/blablachet)
<br>Zimmer [@RemiChambolle](https://twitter.com/RemiChambolle)
<br>J.C [@jordancoude](https://twitter.com/jordancoude)
<br>MaxiSam [@m_axiSam](https://twitter.com/m_axiSam)


# Homer

Homer est projet permettant le déploiement automatisé d'Honeypots, à travers une interface graphique.

Les honeypots disponibles à ce jour sont : 
* SSH
* FTP 
* Agent Windows

## Installation

### Création d'une VM HomerAgent

Cette VM à pour but d'accueillir un Agent Honeypot (ssh ou ftp)

(Installation sur debian 8 netinstall)

* Prérequis : `apt install ansible openssh-server sudo`
* Création d'un utilisateur ansible : `adduser ansible`
* Ajout de l'utilisateur ansible au sudoers sans password : `sudo visudo` et ajouter à la fin : `ansible ALL=(ALL) NOPASSWD: ALL`


### Déploiement de HomerServer

* Prérequis : `docker`
* Build du docker : `docker build . -t homer/server:0.1`
* Lancement du docker : `docker run -d -p 5000:5000 --name homerserver homer/server:0.1`
* Ajout de la clé ssh du HomerAgent :<br>
`docker exec -it homerserver /bin/sh`<br>
`ssh-copy-id ansible@ip_agent`

## Déploiement d'un honeypot

Retrouvez toutes les informations du déploiement sur le [wiki].
[wiki]: https://github.com/P-TE/Homer-Honeypots/wiki/2.-D%C3%A9ploiement-d'un-honeypot


## Architecture

Voici un exemple d'architecture d'un déploiement d'Homer : 



## Auteurs

Blablach [@blablachet]
[@blablachet] https://twitter.com/blablachet
<br>Zimmer [@RemiChambolle][@RemiChambolle] https://twitter.com/RemiChambolle
<br>J.C [@jordancoude][@jordancoude] https://twitter.com/jordancoude
<br>MaxiSam [@m_axiSam][@m_axiSam] https://twitter.com/m_axiSam

## License

Ce projet est sous licence 
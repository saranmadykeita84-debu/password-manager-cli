# Travail Pratique #2: Password-Manager 

## Auteurs
- Saran Mady Keita
## Compatibilité 
Langage – version < Python -- version  3.8 --> 

## Utilisation 
Dans notre programme on a utiliser "visual code" pour réaliser le travail.
Pour pouvoir démarrez notre code il faut ouvrir le terminal dans "visual code" et installer les dépendances avant tout, on tape: pip install cryptography python-dotenv.
puis les dépendances suivant :
beautifulsoup4==4.12.3
certifi==2024.8.30
cffi==1.17.1
charset-normalizer==3.4.0
crypto==1.4.1
cryptography==43.0.3
idna==3.10
Naked==0.1.32
pillow==11.0.0
plyer==2.1.0
pycparser==2.22
pycryptodome==3.21.0
pyler==0.2.0
python-dotenv==1.0.1
PyYAML==6.0.2
requests==2.32.3
shellescape==3.8.1
soupsieve==2.6
sqlcipher3-wheels==0.5.2.post1
ttkbootstrap==1.10.1
urllib3==2.2.3

Ensuite quand l'installation est faite essayer de lancer le programme avec: python src/password.py oubien le button debugger.

-----------------> En première position: Enregistrement de l'utilisateur. <-------------------------------------

Taper python src/password.py -r <username> une fois le name rentré "taper enter" le programme vous demanderait de rentrer un "password:" pour l'utilisateur.

---------------------> Deuxième position: L'ajout d'un mot pour un utilisateur enregistré <-------------------

Taper python src/password.py -u <username> -a <label> <password> une fois rentré "taper enter" le programme vous demanderait de rentrer le "password:" de l'utilisateur. 
Mais dans le password qu'on devrait rentré, c'est le password principal de l'utilisateur .
vous verrez un message vous disant que l'enregistrement du <label> est bien effectué. Mais par contre si le nom de l'utilisateur n'a pas été enregistré ,il ne devrait pas être possible d'ajouter le password. 

-----------------> Troisième position: Affichage d'un mot de passe donné pour un utilisateur donné <--------------------

Taper python src/password.py -u <username> -s <label>  une fois rentré "taper enter" le programme vous demanderait de rentrer le "password:" de l'utilisateur.
Mais dans le password qu'on devrait rentré, c'est toujours le password  principal de l'utilisateur.
Le programme vous affichera le password lié au <label> enregistré.
Mais si l'utilisateur n'existe pas , c'est a dire qu'il na pas été enregistré ,ou que le <label> n'existe pas aussi dans la base de donnée , le programme affichera un message d'erreur.

             ------- Ajout supplémentaire dans le code pour le cadre du bonus----------------- 

----------------------------> Suppression d'un utilisateur <------------------------------------------ 
pour supprimer un utilisateur enregistré , il faut taper la commande :
python src/password.py -d <username> <password> ensuite taper 'enter' et le programme demandera a nouveau d'entrer son password pour confirmer, une fois rentré le programme affichera un message indiquant que l'utilisateur est automatique supprimer avec tout ses 'password' liés avec lui.

---------------------------> Modificiation du code du <label> <----------------------------------------------
pour modifier le code du label enregistré , il faut taper la commande: 
python src/password.py -u <username> -m <label> <NewPassword> ensuite taper 'enter', mais dans ce cas, ce possible si vous essayer de mettre un faible code(ex:1234) le programme vous obligerait de mettre un code fort, car à ce niveau j'ai ajouter un algorithme qui permettrait de tester la robustesse du nouveau password .
si le password contient (un majuscule,un miniscule,un chiffre et des syboles comme @!) le programme accepterai le nouveau password du label .

----------------------------> Suppression du mot de passe du <label> <----------------------------------------
pour supprimer le mot de passe du <label> il suffit de taper la commande:
python src/password.py -u <username> -d <label> ensuite taper 'enter' le programme vous demanderait de rentrer le "password:" de l'utilisateur. Une fois le password rentré vous verrez un message vous disant que le mot de passe du <label> es suprrimé avec succés.

 






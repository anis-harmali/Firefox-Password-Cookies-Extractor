### Installation

*ce script doit-être lancé sous windows (assurez-vous d'avoir installé python au préalable)*

```
pip3 install -r requirements.txt
```
### Execution

Ouvrir PowerShell puis entrer cette commande :

python .\FirefoxExtractor.py --path C:\\Users\\<Nom d'utilisateur>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<A completer>.default-release

*il est necessaire de spécifier le chemin du dossier car son nom est généré aléatoirement par firefox donc different d'un PC à l'autre* 

### Aide
python .\FirefoxExtractor.py --help

### En cas de probleme

*verifiez si le dossier spécifié est le bon, càd contient key4.db et logins.json*

essayer avec cette commande :
py .\FirefoxExtractor.py --path C:\\Users\\<Nom d'utilisateur>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<A completer>.default-<A completer> 


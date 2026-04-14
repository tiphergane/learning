# 🎯 CTF Learning Repository

> Notes personnelles et fiches techniques construites au fil des challenges CTF.
> Chaque technique est documentée **depuis le désassemblage réel** (radare2) — pas de théorie sans vérification.

---

## 📁 Structure

```
.
├── Exploitation_binaire/
│   ├── buffer_overflow_guide.md   ← index + techniques de base
│   ├── canary_exploitation.md     ← Stack Canary Bypass + Format String Leak
│   ├── ret2libc.md                ← Ret2libc simple (binaire dynamique)
│   ├── ret2libc_rop.md            ← Ret2libc + ROP Chain + GOT Leak + binaire statique
│   ├── staged_shellcode.md        ← Stager 13 octets + mmap RWX
│   └── Use_After_Free.md          ← UAF + Function Pointer Hijack
├── Injections/
│   ├── NoSQL/
│   │   └── nosql_injection.md     ← MongoDB $ne bypass + $regex blind
│   ├── SQL/
│   │   └── sql_injection.md       ← Login Bypass, UNION, Blind, Time-based, WAF Bypass
│   └── SSTI/
│       └── SSTI.md                ← SSTI Python + Java
└── README.md
```

---

## 🗺️ Progression

### Exploitation de binaires

| Technique | Statut | Fiche |
|:---|:---:|:---|
| Buffer Overflow simple | ✅ | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| BOF + Condition de Victoire Cachée | ✅ | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Ret2Win | ✅ | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Shellcode Injection + Stack Leak | ✅ | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Stack Canary Bypass + Format String Leak | ✅ | [canary_exploitation.md](Exploitation_binaire/canary_exploitation.md) |
| Use-After-Free + Function Pointer Hijack | ✅ | [Use_After_Free.md](Exploitation_binaire/Use_After_Free.md) |
| Staged Shellcode + mmap RWX | ✅ | [staged_shellcode.md](Exploitation_binaire/staged_shellcode.md) |
| Ret2libc + ROP Chain + GOT Leak | ✅ | [ret2libc_rop.md](Exploitation_binaire/ret2libc_rop.md) |
| Ret2libc binaire statique (system + execve) | ✅ | [ret2libc_rop.md](Exploitation_binaire/ret2libc_rop.md) |

### Injections

| Technique | Statut | Fiche |
|:---|:---:|:---|
| SSTI Python | ✅ | [SSTI.md](Injections/SSTI/SSTI.md) |
| SSTI Java | ✅ | [SSTI.md](Injections/SSTI/SSTI.md) |
| SQL Login Bypass | ✅ | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL UNION-based | ✅ | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL Blind Boolean | ✅ | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL Time-based | ✅ | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL WAF Bypass | ✅ | [sql_injection.md](Injections/SQL/sql_injection.md) |
| NoSQL MongoDB — $ne Bypass + $regex Blind | ✅ | [nosql_injection.md](Injections/NoSQL/nosql_injection.md) |
| SQLite | 🔲 | — |

---

## 🛠️ Environnement

```bash
# Outils utilisés
python3 -m pip install pwntools requests
sudo pacman -S radare2 gdb    # Arch Linux

# Vérifier les protections d'un binaire
checksec --file ./chall

# Workflow radare2
r2 ./chall
aaa        # analyse complète
afl        # liste des fonctions
pdf @ sym.main
afvd       # variables locales + offsets

# Tester une injection SQL manuellement
curl "http://cible.fr/search?id=1'"
sqlmap -u "http://cible.fr/search?id=1" --dbs
```

---

## 📐 Méthodologie

### Exploitation binaire

```
1. checksec            → identifier les protections
2. r2 + afl + afvd     → comprendre la structure du binaire
3. Identifier la vulnérabilité depuis le désassemblage réel
4. Construire l'exploit en vérifiant chaque hypothèse dans r2
5. Documenter avec les hexdumps et désassemblages à l'appui
```

> ⚠️ **Principe de base :** ne jamais accepter une explication sans la vérifier dans radare2.

### Injection SQL

```
1. Identifier le point d'injection (tester ')
2. Identifier le type de réponse (données / oui-non / rien / erreur)
3. Fingerprinter la BDD (@@version, version(), sqlite_version())
4. Cartographier (information_schema)
5. Exfiltrer (UNION / Blind / Time-based selon le contexte)
```

---

## 🏆 Challenges résolus

| Challenge | CTF | Catégorie | Technique | Fiche |
|:---|:---|:---:|:---|:---|
| poney | FCSC 2020 | Pwn | Ret2Win + alignement stack RSP (gadget ret) | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| xortp | FCSC 2025 | Pwn | BOF + ret2libc/ROP execve (binaire statique, faux positif canary checksec) | [ret2libc_rop.md](Exploitation_binaire/ret2libc_rop.md) |
| Aarchibald | FCSC 2019 | Pwn | BOF simple — écrasement de trigger + XOR password (AArch64) | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| bofbof | FCSC 2021 | Pwn | BOF + Condition de Victoire Cachée | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| SQL Project 1 | Opération Kernel 2022 | Web | SQL Login Bypass | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL Project 2 | Opération Kernel 2022 | Web | SQL UNION-based + WAF Bypass | [sql_injection.md](Injections/SQL/sql_injection.md) |
| SQL Project 3 | Opération Kernel 2022 | Web | SQL Blind Boolean + BINARY + hex encoding | [sql_injection.md](Injections/SQL/sql_injection.md) |
| La Cohue | 404CTF 2023 | Pwn | Stack Canary Bypass + Format String Leak | [canary_exploitation.md](Exploitation_binaire/canary_exploitation.md) |
| L'Alchimiste | 404CTF 2023 | Pwn | Use-After-Free + Function Pointer Hijack | [Use_After_Free.md](Exploitation_binaire/Use_After_Free.md) |
| Extractor | Shutlock 2024 | Web | SQL Blind Boolean + WAF Bypass (case mixing) | [sql_injection.md](Injections/SQL/sql_injection.md) |
| Find me 1 | ECW 2022 | Web | NoSQL MongoDB — Login Bypass ($ne) | [nosql_injection.md](Injections/NoSQL/nosql_injection.md) |
| Find me 2 | ECW 2022 | Web | NoSQL MongoDB — Blind $regex (username + password leak) | [nosql_injection.md](Injections/NoSQL/nosql_injection.md) |
| Find me 3 | ECW 2022 | Web | NoSQL MongoDB — Blind $regex avec préfixe ciblé | [nosql_injection.md](Injections/NoSQL/nosql_injection.md) |
| Gorfou en danger 1 | 404CTF 2025 | Pwn | Ret2Win — Buffer Overflow simple | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Gorfou en danger 2 | 404CTF 2025 | Pwn | Shellcode Injection + Stack Leak (NX disabled) | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Gorfou en danger 3 | 404CTF 2025 | Pwn | Ret2libc + ROP Chain + GOT Leak | [ret2libc_rop.md](Exploitation_binaire/ret2libc_rop.md) |
| Puissance 4 | FCSC 2026 | Pwn | Ret2libc + GOT leak manuel via ROP (sans fonction debug) | [ret2libc_rop.md](Exploitation_binaire/ret2libc_rop.md) |
| Spaaaaaaace | 404CTF 2025 | Pwn | Staged Shellcode + mmap RWX | [staged_shellcode.md](Exploitation_binaire/staged_shellcode.md) |

---

*Arch Linux — pwntools — radare2 — GDB + GEF — requests — sqlmap*

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
│   ├── ret2libc.md                ← Ret2libc + ROP Chain + GOT Leak
│   ├── staged_shellcode.md        ← Stager 13 octets + mmap RWX
│   └── Use_After_Free.md          ← UAF + Function Pointer Hijack
├── Injections/
│   ├── SQL/
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
| Ret2Win | ✅ | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Stack Canary Bypass + Format String Leak | ✅ | [canary_exploitation.md](Exploitation_binaire/canary_exploitation.md) |
| Use-After-Free + Function Pointer Hijack | ✅ | [Use_After_Free.md](Exploitation_binaire/Use_After_Free.md) |
| Staged Shellcode + mmap RWX | ✅ | [staged_shellcode.md](Exploitation_binaire/staged_shellcode.md) |
| Ret2libc + ROP Chain + GOT Leak | ✅ | [ret2libc.md](Exploitation_binaire/ret2libc.md) |

### Injections

| Technique | Statut | Fiche |
|:---|:---:|:---|
| SSTI Python | ✅ | [SSTI.md](Injections/SSTI/SSTI.md) |
| SSTI Java | ✅ | [SSTI.md](Injections/SSTI/SSTI.md) |
| SQL | 🔲 | — |
| NoSQL | 🔲 | — |
| SQLite | 🔲 | — |

---

## 🛠️ Environnement

```bash
# Outils utilisés
python3 -m pip install pwntools
sudo pacman -S radare2 gdb    # Arch Linux

# Vérifier les protections d'un binaire
checksec --file ./chall

# Workflow radare2
r2 ./chall
aaa        # analyse complète
afl        # liste des fonctions
pdf @ sym.main
afvd       # variables locales + offsets
```

---

## 📐 Méthodologie

```
1. checksec            → identifier les protections
2. r2 + afl + afvd     → comprendre la structure du binaire
3. Identifier la vulnérabilité depuis le désassemblage réel
4. Construire l'exploit en vérifiant chaque hypothèse dans r2
5. Documenter avec les hexdumps et désassemblages à l'appui
```

> ⚠️ **Principe de base :** ne jamais accepter une explication sans la vérifier dans radare2.
> Les offsets, les registres, les tailles — tout se confirme dans le désassemblage.

---

## 🏆 Challenges résolus

| Challenge | CTF | Technique | Fiche |
|:---|:---|:---|:---|
| La Cohue | 404CTF 2023 | Stack Canary Bypass + Format String Leak | [canary_exploitation.md](Exploitation_binaire/canary_exploitation.md) |
| L'Alchimiste | 404CTF 2023 | Use-After-Free + Function Pointer Hijack | [Use_After_Free.md](Exploitation_binaire/Use_After_Free.md) |
| Gorfou en danger 1 | 404CTF 2025 | Ret2Win — Buffer Overflow simple | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Gorfou en danger 2 | 404CTF 2025 | Shellcode Injection + Stack Leak (NX disabled) | [buffer_overflow_guide.md](Exploitation_binaire/buffer_overflow_guide.md) |
| Gorfou en danger 3 | 404CTF 2025 | Ret2libc + ROP Chain + GOT Leak | [ret2libc.md](Exploitation_binaire/ret2libc.md) |
| Spaaaaaaace | 404CTF 2025 | Staged Shellcode + mmap RWX | [staged_shellcode.md](Exploitation_binaire/staged_shellcode.md) |

---

*Arch Linux — pwntools — radare2 — GDB + GEF*

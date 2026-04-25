## Axis Wiping Utility

[![NIST SP 800-88 Rev. 1](https://img.shields.io/badge/NIST_SP_800--88-Rev._1-blue?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
[![FIPS 140-3 Aligned](https://img.shields.io/badge/FIPS_140--3-Aligned-green?style=flat-square)](https://csrc.nist.gov/publications/detail/fips/140/3/final)
[![RFC 4086 Randomness](https://img.shields.io/badge/RFC_4086-Randomness-orange?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc4086)
[![Language: C](https://img.shields.io/badge/language-C-00599C?style=flat-square&logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Compiler: GCC](https://img.shields.io/badge/compiler-GCC-9cf?style=flat-square&logo=gnu)](https://gcc.gnu.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-blue?style=flat-square&logo=linux)](https://kernel.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)

## 🚀 What is AWU?

**awu** stands for **Axis Wiping Utility**, a serious data‑sanitization tool for people who need to *really* make sure that deleted files, free space, or even volatile memory can never be recovered.  

It follows the same rules that government agencies and security standards demand – we’re talking **military‑grade wiping**, not just a simple delete button.  

---

## 🛡️ Standards & Compliance – The Big Three  

### 1️⃣ NIST SP 800‑88 Rev. 1  
This is the golden standard for media sanitization. AWU aligns directly with it and offers four schemes:  

- **NIST Clear (Baseline)** – overwrite with zeros, per §4.1.  
- **DoD 5220.22‑M (E)** – zero, ones, random (3 passes).  
- **NIST Purge (Multi‑Pass)** – zero, ones, random, then verify.  
- **FIPS High‑Entropy Purge** – multiple random passes, zero, then verify (5 passes).  

You can switch between them anytime in the sanitization settings menu 🎛️.  

### 2️⃣ FIPS 140‑3 (Cryptographic Module Standard)  
Although FIPS 140‑3 is about crypto modules, AWU uses a **FIPS‑grade entropy source** (the kernel’s `getrandom()` via `/dev/urandom`) for all random overwrite passes. That means the random data is as unpredictable as it gets – no predictable patterns ever 🔐.  

### 3️⃣ RFC 4086 (Randomness Requirements for Security)  
The random number generation inside AWU follows the principles from RFC 4086: we don’t use `rand()` or cheap pseudo‑random numbers; instead we pull directly from the OS’s secure random pool, ensuring every byte is cryptographically strong 🎲.  

---

## 💾 What Can AWU Do?

### 🗑️ 1. Sanitize and delete a file  
Wipes the file using the chosen multi‑pass scheme, then renames it, syncs the directory, and finally removes it. It even attempts a **TRIM/discard** on SSDs to help the drive controller release the blocks.

### 📁 2. Sanitize and delete a directory  
Recursively sanitizes every file inside, removes sub‑directories, and finally deletes the root directory. Nothing is left behind.

### 🌌 3. Sanitize free space  
Creates temporary files to fill up all available free space (leaving a tiny 10 MB safety zone). Each chunk is overwritten with the current scheme’s patterns, then all temporary files are deleted and a final TRIM/sync is performed. This catches leftover data from previously deleted files that might still sit in unallocated clusters.

### 🧠 4. Fill RAM (aggressive allocation)  
Allocates huge chunks of memory until only a 250 MB safety margin remains. It touches every page to force the OS to really hand over physical RAM. Why? Because many forensic attacks can read secrets still lingering in RAM after a reboot – this option overwrites that sensitive info live. You can also stop it with Ctrl + C and the memory stays allocated until you manually release it.

### ♻️ 5. Release RAM  
Frees all the memory that was previously locked by option 4. This returns the system to normal operation.

### ⚙️ 6. Sanitization settings  
Lets you pick the security scheme (see the four NIST‑based methods) – perfect when you need to switch from “quick clear” to “high‑entropy purge”.

---

## 🧹 Security‑First Design  

- **`mlock()`** is used whenever possible to prevent buffers from being swapped to disk (otherwise your secrets could leak into the pagefile).  
- **`MADV_DONTNEED`** hints are given after wiping to immediately discard clean copies from RAM.  
- The program **disables core dumps** (`PR_SET_DUMPABLE`) and sets **resource limits** so no crash dump can leak your wiping patterns.  
- It detects **journaling / copy‑on‑write filesystems** (ext4, XFS, btrfs, ZFS, F2FS…) and warns you because those filesystems may still hold residual data in journal areas.  
- All sensitive memory is manually zeroed with `volatile` barriers to prevent compiler optimisations from leaving sensitive data behind.

---

## 🔧 How to Build  

```bash
gcc awu.c -o awu -Wall -Wextra -O2
```

Then run it:  

```bash
sudo ./awu
```

(Some features like TRIM or freeing system memory might need root – but always be careful when running as superuser!)

---

## ⚠️ Warnings (please read!)

- This tool is **irreversible** – once you sanitize something, there is no undo.  
- Always test on non‑critical data first.  
- On SSDs, guaranteed sanitization is impossible due to wear‑levelling and over‑provisioning; the TRIM attempt helps, but full physical destruction is the only 100% method for flash media.  
- The RAM‑fill option can make your system unresponsive or trigger the OOM killer – save your work first!

---

## 📜 License & Responsibility  

**awu** is provided as‑is for lawful data sanitization in controlled environments. The author is not responsible for misuse or data loss. Respect your local laws and company policies.  

---

## 💬 Final words  

AWU is that **heavy‑duty, no‑nonsense wiping tool** that you hope you’ll never *actually need*, but when you do, it follows the same playbook as government defense agencies. Use it wisely, and always keep a cold backup of anything you might regret deleting 😉

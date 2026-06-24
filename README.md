# 🛡️ Sentinel-IAM

> Real-time SSH intrusion detection pipeline powered by Java, RabbitMQ, ChromaDB and a Groq LLM.

---

## Architecture

```
/var/log/auth.log
       │
       ▼
 surveille.sh          ← tail -f | grep "Failed" | nc
       │
       ▼
 Java Server (port 8080)
  ├── LogParser         ← parse les lignes syslog (RFC 3164)
  ├── LogSecurity       ← objet structuré (date, server, user, IP)
  └── LogProducer       ← publie en JSON sur RabbitMQ
       │
       ▼
 RabbitMQ (queue: security_alerts)
       │
       ▼
 ia_receiver.py
  ├── store_alert()     ← stocke dans ChromaDB (vecteur)
  ├── mask_data()       ← masque user + IP avant envoi cloud (RGPD)
  └── Groq LLM          ← recommandation de mitigation en temps réel
       │
       ▼
 dashboard.py (Flask — port 5000)
  ├── /live             ← alertes en temps réel
  ├── /stats            ← top IPs et usernames (Chart.js)
  └── /ask              ← RAG assistant (ChromaDB + Groq, SSE streaming)
```

---

## Prérequis

- Java 11+
- Python 3.10+
- Docker (pour RabbitMQ)
- Un compte Groq → [console.groq.com/keys](https://console.groq.com/keys)

---

## Installation

### 1. Cloner le projet

```bash
git clone https://github.com/ton-user/Sentinel-IAM.git
cd Sentinel-IAM
```

### 2. Configurer la clé API Groq

```bash
echo 'GROQ_API_KEY=gsk_VOTRE_CLE_ICI' > .env
```

### 3. Installer les dépendances Python

```bash
pip install -r requirements.txt
```

### 4. Compiler le serveur Java

```bash
./compile.sh
```

---

## Lancement

Ouvre **5 terminaux** dans le dossier du projet.

**Terminal 1 — Java Server**
```bash
./compile.sh
```
> Attend : `[*] Server started on port 8080. Waiting for connections...`

**Terminal 2 — RabbitMQ**
```bash
docker run -d --name rabbit -p 5672:5672 rabbitmq:3
```

**Terminal 3 — Python AI Consumer**
```bash
python3 ia_receiver.py
```
> Attend : `[*] Python AI Listener started. Waiting for alerts from Java.`

**Terminal 4 — Flask Dashboard**
```bash
python3 dashboard.py
```
> Ouvre [http://localhost:5000](http://localhost:5000)

**Terminal 5 — Surveillance des logs**
```bash
# Production (logs réels)
./surveille.sh

# Test manuel (simulation d'une attaque)
echo 'Jan 15 10:23:45 webserver01 sshd[4521]: Failed password for root from 1.2.3.4 port 22 ssh2' | nc localhost 8080
```

---

## Dashboard

| Page | Description |
|---|---|
| `/live` | Tableau des alertes en temps réel, rafraîchi toutes les 10s |
| `/stats` | Graphiques top 10 IPs et top 5 usernames ciblés |
| `/ask` | Assistant RAG — pose des questions sur tes alertes en langage naturel |

---

## Stack technique

| Composant | Technologie |
|---|---|
| Log parsing | Java 11, Regex RFC 3164 |
| Message broker | RabbitMQ (amqp-client 5.16) |
| Sérialisation | Gson 2.10 |
| Vector store | ChromaDB + LangChain + sentence-transformers (all-MiniLM-L6-v2) |
| LLM | Groq — `openai/gpt-oss-120b` |
| Dashboard | Flask 3.1, Bootstrap 5, Chart.js, SSE streaming |
| PII masking | Redaction user + IP avant tout envoi cloud |

---

## Sécurité & RGPD

- Les champs `user` et `ip` sont **masqués** avant d'être envoyés à l'API Groq cloud.
- Les données brutes restent en local dans ChromaDB (`./chroma_db/`).
- Le fichier `.env` est exclu du dépôt git via `.gitignore`.

---

## Structure du projet

```
Sentinel-IAM/
├── Server/
│   ├── Main.java
│   ├── Server.java
│   ├── Exception/
│   │   └── SocketServerNotCreated.java
│   └── Log/
│       ├── LogParser.java
│       ├── LogSecurity.java
│       ├── LogProducer.java
│       └── IPAdress.java
├── templates/
│   ├── base.html
│   ├── live.html
│   ├── stats.html
│   └── ask.html
├── ia_receiver.py
├── rag_store.py
├── dashboard.py
├── compile.sh
├── surveille.sh
├── requirements.txt
└── .env          ← à créer manuellement (non versionné)
```

---

## Auteur

**Youssef El Akoum** — Étudiant ingénieur INSA Rouen Normandie, spécialisation ITI (IA & Cybersécurité)

[LinkedIn](https://linkedin.com/in/youssef-el-akoum) · [GitHub](https://github.com/yelakoum)

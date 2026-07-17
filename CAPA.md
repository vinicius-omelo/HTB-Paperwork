Este repositório foi criado para documentar, de forma didática, a resolução da máquina Paperwork do Hack The Box, como parte dos meus estudos na pós-graduação em Offensive Cyber Security (Red Team) na FIAP.
O objetivo é registrar o processo completo de exploração — reconhecimento, obtenção de acesso inicial, escalada de privilégios — explicando não só os comandos usados, mas o porquê de cada vulnerabilidade existir e como identificá-la em cenários reais.
Sobre a máquina
Paperwork envolve exploração de um serviço LPD customizado (injeção de comando), path traversal em um protocolo JetDirect/PJL, e vazamento de credenciais via file descriptor em um Unix socket (SCM_RIGHTS) — uma cadeia que passa por três vulnerabilidades diferentes até chegar a root.

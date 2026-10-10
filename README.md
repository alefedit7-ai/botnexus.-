# BotNexus

Painel inicial em Node.js/Express para cadastrar contas, armazenar projetos ZIP e administrar registros de bots. Interface responsiva em preto e azul neon.

## Requisitos

- Node.js 20 ou superior
- npm
- Um computador/servidor ou ambiente Android que consiga instalar dependências nativas. `better-sqlite3` pode não compilar em alguns ambientes Android.

## Instalação

1. Extraia o ZIP.
2. Abra um terminal dentro da pasta `BotNexus`.
3. Instale dependências:

   ```bash
   npm install
   ```

4. Copie `.env.example` para `.env`.
5. Altere `SESSION_SECRET` para uma chave longa e aleatória. Em produção, defina `NODE_ENV=production` e `COOKIE_SECURE=true` quando o site estiver atrás de HTTPS.
6. Inicie:

   ```bash
   npm start
   ```

7. Abra `http://localhost:3000` no mesmo dispositivo, ou acesse o endereço fornecido pelo seu ambiente de hospedagem.

## O que funciona nesta versão

- Cadastro e login com senha armazenada por hash bcrypt.
- Sessão persistida em SQLite.
- Dashboard com bots pertencentes ao usuário autenticado.
- Upload de ZIP com limite de tamanho e validação simples de extensão.
- Registro de logs e visualização em tempo real por Socket.IO.
- Ações de iniciar/parar com **status demonstrativo**.
- Exclusão de projeto e arquivo ZIP.

## Limitação de segurança essencial

**Este projeto não executa o código enviado nos ZIPs.** Os botões iniciar/parar alteram somente o status de demonstração. Isto é intencional: executar código arbitrário de usuários diretamente no processo do painel pode comprometer o servidor, banco de dados, tokens e outros usuários.

Para oferecer hospedagem real, crie um worker separado que execute cada bot em container isolado (por exemplo, Docker), com usuário não privilegiado, limites de CPU/RAM/PIDs, sistema de arquivos restrito, rede controlada, timeout, quotas e política de logs. O worker não deve ter acesso à sessão, banco do painel, variáveis secretas ou arquivos de outros usuários. Revise a segurança antes de expor o serviço à internet.

## Recomendações antes de publicar

- Use HTTPS.
- Configure `SESSION_SECRET` forte e único.
- Configure `COOKIE_SECURE=true` apenas quando HTTPS estiver habilitado.
- Adicione proteção CSRF aos formulários de alteração e limite de tentativas de login.
- Configure rate limiting, backups, quotas e monitoramento.
- Nunca coloque tokens reais de Discord no repositório, ZIP ou logs.
- Faça upload somente de projetos que você tem direito de usar.
- Não exponha o painel sem revisar autenticação, CSRF, rate limiting e isolamento do worker.

## Estrutura

```text
BotNexus/
├── public/
│   └── style.css
├── data/                 # criado ao iniciar (não versionar)
├── storage/              # ZIPs enviados (não versionar)
├── .env.example
├── .gitignore
├── package.json
├── server.js
└── README.md
```

## Teste de sintaxe

```bash
npm run check
```

Este comando verifica a sintaxe do `server.js`; não substitui testes funcionais e de segurança.

# 🔐 Auth - Serviço de Identidade, Autenticação e Painel Admin

O **Auth** é o serviço central de identidade de um ecossistema distribuído (ex.: `Fin-API`). Desenvolvido em **.NET 10**, ele gerencia usuários, login, emissão de tokens JWT assinados via **JWKS**, refresh tokens, sistemas, perfis (roles) e permissões granulares (claims).

> 🤖 **Estratégia AI-First:** Para contexto arquitetural rápido, regras e armadilhas conhecidas, leia [CONTEXT.md](CONTEXT.md).

---

## 🏗️ Papel no Ecossistema

1. **Emissão de Tokens (JWKS):** Gera tokens JWT assinados assimetricamente (`Jovanne.Jwks` + `NetDevPack.Security.Jwt`), com endpoint de descoberta JWKS para validação pelos demais serviços.
2. **Sincronização de Usuários:** Ao registrar um novo usuário, notifica os sistemas dependentes via **RabbitMQ** (`Jovane.MessageBus`, padrão Request/Response) para garantir consistência.
3. **Controle de Acesso:** Gerencia permissões granulares no formato `SISTEMA:ACAO` (ex.: `AUTH:LER`, `FIN:TRN_CRIAR`).
4. **Painel Administrativo (`Auth.Client`):** Frontend em Blazor WebAssembly + MudBlazor para gestão de usuários, sistemas, roles e claims.

---

## 🚀 Tecnologias

- **.NET 10** (`Auth.Api`, `Auth.Application`, `Auth.Domain`, `Auth.Infra`, `Auth.Client`)
- **ASP.NET Core Identity + Entity Framework Core + PostgreSQL (`Npgsql`)**
- **Dapper** (consultas de leitura otimizadas)
- **Jovanne.Jwks & NetDevPack.Security.Jwt** (gestão de chaves e JWT)
- **Jovane.MessageBus (RabbitMQ)** (integração assíncrona)
- **Blazor WebAssembly + MudBlazor** (painel administrativo)

---

## 🔌 Principais Endpoints

### Autenticação & Usuários (`/api/auth`)
| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/registrar` | Cadastra usuário (ou vincula perfil) e sincroniza via RabbitMQ. |
| `POST` | `/login` | Valida credenciais, checa permissão no sistema e retorna JWT + Refresh Token. |
| `POST` | `/refresh-token` | Gera novo JWT a partir de um `RefreshToken` válido. |
| `POST` | `/forgot-password` | Gera token de reset e publica evento de e-mail no RabbitMQ. |
| `POST` | `/reset-pass` | Redefine a senha utilizando token válido. |
| `GET` | `/listar-usuarios` | Lista usuários e vínculos de sistemas (`[ClaimsAuthorize("AUTH:LER")]`). |
| `GET` | `/details-user/{id}` | Detalhes de um usuário por ID (`[ClaimsAuthorize("AUTH:LER")]`). |
| `DELETE` | `/excluir/{id}` | Remove um usuário. |
| `GET` | `/health` | Check de saúde da API. |

### Sistemas, Roles & Claims (`/api/sistema`, requer `[Authorize]`)
| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `GET` / `POST` / `PUT` | `/api/sistema` | Lista, cria ou atualiza sistemas cadastrados. |
| `POST` | `/api/sistema/roles` | Adiciona uma role vinculada a um sistema. |
| `DELETE` | `/api/sistema/roles/remover/{roleId}` | Remove uma role (se não possuir claims). |
| `POST` | `/api/sistema/claim` | Associa uma claim `permission` a uma role. |
| `DELETE` | `/api/sistema/claim/excluir/{roleId}/{claimValue}` | Remove uma claim de uma role. |

---

## 📚 Documentação do Projeto

- [CONTEXT.md](CONTEXT.md) — Contexto AI-First, estrutura da solution, arquivos-chave e débitos técnicos conhecidos.
- [docs/client-integration-guide.md](docs/client-integration-guide.md) — Guia de integração para novos sistemas e apps clientes (contratos de Login, Refresh Token, Registro e Reset de Senha).
- [docs/flows.md](docs/flows.md) — Mapeamento detalhado dos fluxos existentes com diagramas.
- [docs/git-workflow.md](docs/git-workflow.md) — Estratégia de branches intermediárias (`preview` -> `main`), commits e PRs.

---

## 🛠️ Como Executar

1. Certifique-se de que **PostgreSQL** e **RabbitMQ** estejam ativos e configurados em `appsettings.Development.json` (incluindo `ConnectionStrings:DefaultConnection` e `FrontEndSettings:AllowedApps`).
2. Aplique as migrations:
   ```powershell
   dotnet ef database update --project Src/Auth.Infra --startup-project Src/Auth.Api
   ```
3. Inicie a API:
   ```powershell
   dotnet run --project Src/Auth.Api/Auth.Api.csproj
   ```
4. *(Opcional)* Inicie o painel Blazor WebAssembly:
   ```powershell
   dotnet run --project Src/Auth.Client/Auth.Client.csproj
   ```

---

## 📝 Autor

Desenvolvido por **Jovane Sousa**.

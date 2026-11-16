# CONTEXT.md — Auth Ecosystem (.NET 10)

> **Propósito:** Fonte única de verdade para agentes de IA e desenvolvedores entenderem rapidamente a arquitetura, fluxos, convenções, armadilhas conhecidas e regras de contribuição deste repositório.

---

## 1. Visão Geral

Serviço central de **Identidade e Autenticação (IdP)** para um ecossistema distribuído (ex.: `Fin-API`), composto por uma API REST em **.NET 10** e um painel administrativo em **Blazor WebAssembly**.

- **Autenticação & Autorização:** ASP.NET Core Identity + JWT assinado assimetricamente via **JWKS** (`Jovanne.Jwks` + `NetDevPack.Security.Jwt`).
- **Permissões granulares:** Claims do tipo `"permission"` no formato `SISTEMA:ACAO` (ex.: `AUTH:LER`, `FIN:TRN_CRIAR`).
- **Persistência:** PostgreSQL via **EF Core** (escrita/Identity/JWKS/RefreshToken) e **Dapper** (consultas de leitura complexas).
- **Mensageria:** RabbitMQ via `Jovane.MessageBus` (Request/Response no registro de usuário; Pub/Sub na recuperação de senha).
- **Frontend:** Blazor WebAssembly + MudBlazor (`Auth.Client`), servido estaticamente pela `Auth.Api` em produção (`Dockerfile`).

---

## 2. Estrutura da Solution (`auth.sln`)

| Projeto | Responsabilidade | Observações |
| :--- | :--- | :--- |
| `Src/Auth.Api` | Entry point, Controllers, Middleware, DI, Cors, DbContext, Swagger, Host do Blazor | `net10.0`. Requer `DefaultConnection` e `FrontEndSettings:AllowedApps` no startup. |
| `Src/Auth.Application` | Regras de negócio (`Services`), leitura (`Queries` com Dapper), DTOs e Extensions | Usa `INotificador` (Notification Pattern) via `BaseService` / `BaseQueryService`. |
| `Src/Auth.Domain` | Entidades, ViewModels, Models, Extensions e Exceptions | `Interfaces/**` é excluído no `.csproj`. |
| `Src/Auth.Infra` | `ApplicationDbContext`, Identity (`ApplicationUser`, `ApplicationRole`), Repositórios, `Notificador`, Migrations | Implementa `ISecurityKeyContext` (`SecurityKeys`). |
| `Src/Auth.Client` | UI administrativa em Blazor WASM + MudBlazor (`Users`, `Systems`, `Dialogs`) | `Nullable` desabilitado. Em Dev aponta para `http://localhost:5071`. |
| `Tests/Auth.UnitTests` | Projeto de testes unitários | Atualmente apenas placeholder (`Class1.cs`), sem pacotes de teste configurados. |

---

## 3. Arquivos Essenciais para Leitura (Antes de Alterar Código)

Quando iniciar uma tarefa neste repositório, leia apenas os arquivos relevantes para o escopo:

1. **Bootstrap & Infraestrutura da API:**
   - `Src/Auth.Api/Program.cs` — Pipeline HTTP, JWKS (`AddJovanneJwksFull` / `UseJwksDiscovery`), Swagger e fallback Blazor.
   - `Src/Auth.Api/Configuration/DiConfig.cs` — Registro de dependências (Repositories, Services, QueryServices, Notificador).
   - `Src/Auth.Api/Configuration/DbContextConfig.cs` e `CorsConfig.cs` — Requisitos obrigatórios de configuração.
2. **Endpoints & Contratos:**
   - `Src/Auth.Api/Controllers/ApiController.cs` — Padrão de resposta `CustomResponse` (`{ success, data }` ou `{ success: false, errors }`).
   - `Src/Auth.Api/Controllers/AuthController.cs` — Fluxos de usuário, login, senha e refresh token.
   - `Src/Auth.Api/Controllers/SistemaController.cs` — Gestão de sistemas, roles e claims (`[Authorize]`).
3. **Regras de Negócio & Consultas:**
   - `Src/Auth.Application/Services/AuthService.cs` e `SystemService.cs` — Lógica principal.
   - `Src/Auth.Application/Queries/AuthQueryService.cs` e `SystemQueryService.cs` — Queries SQL/Dapper.
4. **Dados & Identity:**
   - `Src/Auth.Infra/Data/ApplicationDbContext.cs` — DbSets e índices (`SystemId + Name` único em `AspNetRoles`).
   - `Src/Auth.Infra/Repositories/AuthRepository.cs` e `SystemRepository.cs`.

---

## 4. Mapa Resumido dos Fluxos Existentes

> Detalhamento completo com diagramas em [docs/flows.md](docs/flows.md).

- **Registro de Usuário (`POST /api/auth/registrar`):**
  1. Se e-mail não existe, cria `ApplicationUser` no Identity (`EmailConfirmed = true`). Se já existe, valida a senha atual via `PasswordSignInAsync` para permitir vínculo a novo perfil/sistema.
  2. Envia `UsuarioRegistradoIntegrationEvent` via `_messageBus.RequestAsync<..., ResponseMessage>` aguardando confirmação síncrona do serviço consumidor (ex.: `Fin-API`).
  3. Se válido, associa a role (`registerUser.Profile`) ao usuário.
- **Login (`POST /api/auth/login`):**
  1. Valida credenciais (`PasswordSignInAsync` + `SignInAsync`).
  2. Busca claims das roles do usuário (`ObterClaimsPorUsuarioAsync`) e valida se existe alguma claim `"permission"` começando com `loginUser.System.ToUpper()`.
  3. Gera JWT assinado com chave JWKS atual (`Expires = +1h`, `Issuer = {scheme}://{host}`) e gera `RefreshToken` (GUID persistido no banco, substituindo tokens anteriores do mesmo `UserName`).
- **Refresh Token (`POST /api/auth/refresh-token`):**
  1. Valida formato GUID, busca `RefreshToken` no banco e verifica `ExpirationDate` (`isValid()`).
  2. Gera novo JWT para o `System` informado, rotaciona o `RefreshToken` e retorna `CustomResponse(new { token = LoginResponseViewModel })`.
- **Recuperação de Senha (`POST /api/auth/forgot-password` e `reset-pass`):**
  1. `forgot-password`: gera token de reset no Identity, monta `{_frontUrl}/auth?email=...&token=...` e publica `EmailIntegrationEvent` no RabbitMQ (`_messageBus.PublishAsync`). Sempre retorna `true` se usuário não existir ou e-mail não confirmado.
  2. `reset-pass`: aplica `ResetarSenha` com token e nova senha.
- **Gestão de Usuários (`GET /api/auth/listar-usuarios`, `details-user/{id}`, `DELETE /api/auth/excluir/{id}`):**
  1. Listagem e detalhes protegidos por `[ClaimsAuthorize("AUTH:LER")]`, executados via Dapper (`AuthQueryService`).
- **Gestão de Sistemas, Roles e Claims (`/api/sistema`):**
  1. Controller protegida por `[Authorize]`.
  2. CRUD parcial de `SystemEntity`, adição/remoção de `ApplicationRole` (bloqueia remoção se houver claims associadas) e adição/remoção de `Claim("permission", value)`.

---

## 5. Convenções, Padrões e Armadilhas Conhecidas (Tech Debt)

Ao gerar código ou diagnosticar bugs, considere os seguintes fatos reais do código atual:

- **Notification Pattern:** Serviços **não** lançam exceções de negócio para o controller; notificam via `_notificador.Handle(...)` (ou `RetornaErroProcessamento<T>(...)` / `ExecuteAsync(...)` em `BaseService`) e retornam `default`/`false`.
- **Exclusão de usuário desativada (`AuthRepository.DeleteAsync`):** Atualmente retorna `IdentityResult.Success` com a chamada `_userManager.DeleteAsync(usuario)` comentada (`Src/Auth.Infra/Repositories/AuthRepository.cs:55-57`).
- **Remoção de sistema não implementada:** `SystemService.RemoveSistemaAsync` lança `NotImplementedException`.
- **Hard-fail no Startup:** Sem `ConnectionStrings:DefaultConnection` e `FrontEndSettings:AllowedApps` (array não vazio), a API falha ao iniciar.

---

## 6. Comandos Úteis

```powershell
# Restaurar e compilar toda a solution
dotnet restore auth.sln
dotnet build auth.sln

# Executar a API (Swagger em /swagger no ambiente Development)
dotnet run --project Src/Auth.Api/Auth.Api.csproj

# Executar o Client Blazor WASM (requer API em http://localhost:5071)
dotnet run --project Src/Auth.Client/Auth.Client.csproj

# Aplicar migrations no PostgreSQL
dotnet ef database update --project Src/Auth.Infra --startup-project Src/Auth.Api

# Build via Docker (compila Client + Api em imagem única)
docker build -t auth-api .
```

---

## 7. Fluxo Git, Commits e PRs

Este projeto adota **branchs intermediárias** antes do merge na `main` e padrão estruturado de commits e Pull Requests. Consulte as regras completas em [docs/git-workflow.md](docs/git-workflow.md) e o template em [.github/pull_request_template.md](.github/pull_request_template.md).

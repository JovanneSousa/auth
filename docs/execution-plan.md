# Plano de Execução — Finalização dos Fluxos de Auth, Gestão de Sistemas e Painel Admin

> **Contexto:** O serviço central de identidade (`Auth.Api` + `Auth.Client`) possui a estrutura base de JWKS, Identity, Dapper e MudBlazor implementada, porém há fluxos incompletos (CRUD de sistemas, autenticação no painel admin Blazor, exclusão de usuário, expiração/rotação de refresh token) e bugs que impedem o uso seguro em produção.

---

## Fase 1 — Correções Críticas de Auth e Contratos (Backend)

- [x] **Registrar `AppTokenSettings` no DI**
  - Configurar `AppTokenSettings` em `Src/Auth.Api/Configuration/SettingsConfig.cs` e definir `RefreshTokenExpiration` no `appsettings.json`.
  - Hoje o valor padrão fica `0`, fazendo com que todo `RefreshToken` gerado já nasça expirado.
- [x] **Corrigir `RefreshToken.isValid()` e validar/rotacionar no `AuthService.RefreshToken`**
  - Corrigir `Src/Auth.Domain/Entities/RefreshToken.cs` para comparar `ExpirationDate` em UTC com `DateTime.UtcNow` (remover `.ToLocalTime()`).
  - Validar se o token não está expirado em `AuthService.RefreshToken` e implementar rotação (gerar novo `RefreshToken` e invalidar o anterior).
- [x] **Padronizar contrato de retorno do `RefreshToken`**
  - Alinhar o retorno de `POST /api/auth/refresh-token` em `AuthController.cs` com o formato de `LoginResponseViewModel` (ou contrato consistente contendo `AccessToken` + `RefreshToken`).
- [x] **Corrigir validação de permissão por sistema (`UsuarioTemPermissao`)**
  - Em `AuthService.cs`, validar se o sistema informado existe em `SystemEntity` e verificar o prefixo com separador (`$"{system.ToUpper()}:"`) em vez de apenas `StartsWith(system)`.
- [x] **Corrigir vínculo de Role por Sistema (`SalvaUserRoles`)**
  - `ApplicationDbContext` define índice único composto `(SystemId, Name)` em `AspNetRoles`, permitindo nomes de role iguais em sistemas distintos.
  - Substituir o uso de `_userManager.AddToRoleAsync(user, role)` por busca explícita da role considerando `SystemId + Name` para evitar conflito ou vínculo no sistema errado.
- [x] **Corrigir `Dapper splitOn` na listagem de usuários**
  - Ajustar `splitOn: "RoleId, SystemId"` em `AuthQueryService.ObterUsuariosComSistemas()` (`Src/Auth.Application/Queries/AuthQueryService.cs`).

---

## Fase 2 — Segurança e Finalização do CRUD de Sistemas e Usuários (Backend)

- [ ] **Proteger endpoints administrativos com Claims**
  - Substituir `[Authorize]` genérico em `SistemaController` por `[ClaimsAuthorize("AUTH:...")]` (ex.: `AUTH:LER`, `AUTH:ESCREVER`, `AUTH:EXCLUIR` ou `AUTH:ADMIN`).
  - Adicionar `[ClaimsAuthorize("AUTH:...")]` em `DELETE /api/auth/excluir/{id}` (`AuthController.cs`).
- [ ] **Corrigir retornos silenciosos em `SystemService` e tratamento de erro no repositório**
  - Adicionar `return` nas chamadas `RetornaErroProcessamento<bool>(...)` em `SystemService.AtualizaSistemaAsync` e `SystemService.RemoverRole`.
  - Envolver `SystemRepository.AtualizarAsync` com `ExecuteAsync(...)` do `BaseRepository`.
- [ ] **Implementar remoção de sistema (`DELETE /api/sistema/{id}`)**
  - Adicionar action `DELETE` em `SistemaController.cs`.
  - Implementar `SystemService.RemoveSistemaAsync(string sistemaId)` (atualmente lança `NotImplementedException`), validando se existem roles/usuários vinculados antes da exclusão.
- [ ] **Reativar exclusão/desativação de usuário**
  - Corrigir `AuthRepository.DeleteAsync` (atualmente retorna `IdentityResult.Success` com `_userManager.DeleteAsync(usuario)` comentado) — definir entre exclusão física ou soft delete/bloqueio.
- [ ] **Criar endpoint de listagem de usuários por sistema**
  - Expor `GET /api/sistema/{id}/usuarios` (ou filtro em `AuthQueryService`) retornando usuários e suas roles vinculadas àquele sistema.
- [ ] **Desacoplar registro de usuário para novos sistemas sem consumidor RabbitMQ**
  - Evitar usuário órfão no Identity quando `CriaUserIdentity` sucede mas `_messageBus.RequestAsync` falha/dá timeout.
  - Tornar a sincronização via RabbitMQ configurável por sistema (ou implementar compensação removendo o usuário recém-criado em caso de falha na integração).

---

## Fase 3 — Autenticação e Fluxos Incompletos no Painel Admin (`Auth.Client`)

- [ ] **Implementar tela e fluxo de Login no `Auth.Client`**
  - Criar página `/login` contendo **apenas os campos de login (e-mail) e senha**, sem opções de reset de senha ou criação/registro de usuário na tela de login.
  - Autenticar via `POST /api/auth/login` direcionado ao sistema `AUTH`.
  - Criar `AuthenticationStateProvider` customizado, armazenamento de `AccessToken`/`RefreshToken` e `DelegatingHandler` para injetar `Authorization: Bearer <token>` nas requisições HTTP (com renovação automática via `/api/auth/refresh-token` quando expirado).
  - Redirecionar usuários não autenticados para `/login` e tratar respostas `401`/`403` sem corpo JSON em `ApiService.cs`.
- [ ] **Finalizar Edição e Exclusão de Sistemas em `Systems.razor` e `CreateSystemDialog.razor`**
  - Corrigir o parâmetro `IsEdiging` (renomear para `IsEditing`) e passá-lo como `true` ao abrir o diálogo de edição em `Systems.razor`.
  - Implementar `CreateSystemDialog.AtualizarSistema` chamando `PUT /api/sistema`.
  - Implementar `Systems.RemoverSistema` chamando `DELETE /api/sistema/{id}` com confirmação.
- [ ] **Implementar aba "Usuários" em `Systems.razor`**
  - Consumir o endpoint de usuários por sistema e permitir vincular usuários existentes a uma role do sistema.
- [ ] **Corrigir bugs nos Dialogs (`CreateRoleDialog.razor` e `CreateUserDialog.razor`)**
  - Remover chamadas duplicadas a `MudDialog.Close(DialogResult.Ok(...))` no `Submit()` que fecham o modal mesmo quando a API retorna erro.
  - Remover o hardcode `if (user.System.Equals("financeiro", ...)) user.System = "fin";` em `CreateUserDialog.razor`.

---

## Fase 4 — Qualidade e Testes (`Tests/Auth.UnitTests`)

- [ ] **Configurar framework de testes**
  - Adicionar `xUnit` e `Moq` (ou `NSubstitute`) ao `Auth.UnitTests.csproj` e remover o placeholder `Class1.cs`.
- [ ] **Cobrir cenários críticos com testes unitários**
  - `AuthService.LogarUsuarioAsync` (validação de credenciais, lockout, regra de permissão por sistema).
  - `AuthService.RefreshToken` (token inválido, expirado, válido e rotação).
  - `AuthService.AdicionarUsuarioAsync` (novo usuário, vínculo em segundo sistema, falha de integração RabbitMQ).
  - `SystemService` (criação, edição, bloqueio/remoção de sistema e bloqueio de remoção de role com claims).

---

## Critérios de Aceite

1. O painel `Auth.Client` exige login (apenas login e senha, sem reset ou auto-cadastro) e envia JWT válido em todas as chamadas protegidas.
2. Um administrador autenticado consegue criar, editar e remover sistemas, gerenciar roles/claims e visualizar/vincular usuários ao sistema sem erros `401` ou `NotImplementedException`.
3. `RefreshToken` valida `ExpirationDate` configurado em `AppTokenSettings` e rotaciona o token ao ser utilizado.
4. Endpoints administrativos (`SistemaController` e exclusão de usuários) exigem claims administrativas do sistema `AUTH`.
5. `dotnet build auth.sln` e `dotnet test auth.sln` executam sem erros.

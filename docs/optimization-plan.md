# Plano de Otimização de Performance — Redução de Latência Sem Alterar Comportamento

> **Objetivo:** Revisar e otimizar todos os endpoints de `AuthController` e `SistemaController`, suas camadas de serviço (`AuthService`, `SystemService`), consultas Dapper (`AuthQueryService`, `SystemQueryService`) e repositórios EF Core/Identity (`AuthRepository`, `SystemRepository`), **reduzindo o tempo de resposta (roundtrips ao banco, alocações e operações redundantes) sem alterar nenhum contrato HTTP, mensagem de erro ou comportamento funcional**.
>
> **Regra de Ouro:** A suíte de 39 testes unitários em `Tests/Auth.UnitTests` deve continuar passando integralmente após cada etapa (e novos testes devem ser adicionados caso novos métodos de repositório sejam criados).

---

## Etapa 1 — Otimização do `AuthController` (`/api/auth`)

### 1.1 `POST /api/auth/login` (`AuthService.LogarUsuarioAsync`)
**Diagnóstico atual (~7 a 8 roundtrips ao banco por login):**
1. `ObterUsuarioPorEmailAsync` busca o `ApplicationUser`.
2. `_signInManager.PasswordSignInAsync(user.UserName, ...)` busca o mesmo `ApplicationUser` **novamente** no banco (`FindByNameAsync`) e monta um `ClaimsPrincipal` completo (consultando roles e claims) para emitir cookie de sessão.
3. Logo abaixo, `_signInManager.SignInAsync(user, false)` é chamado **de novo**, refazendo as consultas de claims/roles e gerando cookie pela segunda vez (desnecessário em API JWT stateless).
4. `UsuarioTemPermissao` chama `_authRepository.SistemaExisteAsync` (até 2 queries `AnyAsync`) **antes** de checar a lista `claims` que já está carregada em memória.
5. `updateRefreshToken` executa `RemoveRange(_context.RefreshTokens.Where(...))`, o que faz um `SELECT` de todos os tokens antigos para a memória antes do `DELETE`.

**Otimizações a aplicar (Redução para ~3 roundtrips):**
- [x] Substituir `PasswordSignInAsync` + `SignInAsync` por `_signInManager.CheckPasswordSignInAsync(user, loginUser.Password, lockoutOnFailure: true)` (valida senha, confirmação e aplica lockout no Identity sem reconsultar o usuário nem emitir cookies inúteis).
- [x] Em `UsuarioTemPermissao`, inverter a ordem: verificar primeiro em memória (`claims.Any(...)`) se o usuário já possui claim `permission` com o prefixo `"{SYSTEM}:"`. Só consultar `_authRepository.SistemaExisteAsync` no banco quando `hasPermission == false` (para diferenciar os erros `"Sistema não encontrado!"` vs `"Usuário não tem permissão nesse sistema!"`). Em 100% dos logins válidos, elimina 1 a 2 queries no banco.
- [x] Em `AuthRepository.ObterClaimsPorUsuarioAsync`, adicionar `.AsNoTracking()` e usar `JOIN` explícito entre `RoleClaims` e `UserRoles` em vez de subquery `Contains`.
- [x] Em `AuthRepository.updateRefreshToken`, usar `ExecuteDeleteAsync()` para remover tokens antigos do usuário sem carregá-los na memória do EF Core.

---

### 1.2 `POST /api/auth/refresh-token` (`AuthService.RefreshToken`)
**Diagnóstico atual:**
- Carrega o `RefreshToken`, busca o usuário, monta as claims (executando `SistemaExisteAsync` mesmo quando o usuário já tem a claim em memória), gera o JWT e substitui o `RefreshToken`.

**Otimizações a aplicar:**
- [x] Beneficiar-se automaticamente da inversão em `UsuarioTemPermissao` (0 queries extras de `SistemaExisteAsync` quando o usuário possui permissão), do `JOIN` otimizado em `ObterClaimsPorUsuarioAsync` e do `ExecuteDeleteAsync()` em `updateRefreshToken`.
- [x] Remover a verificação duplicada de `user ??= await ObterUsuarioPorEmailAsync` dentro de `GenerateJwt` quando `user` e `claims` já foram resolvidos em `RefreshToken` e `LogarUsuarioAsync`.

---

### 1.3 `POST /api/auth/registrar` (`AuthService.AdicionarUsuarioAsync`)
**Diagnóstico atual (~6 a 8 roundtrips ao banco):**
1. `AdicionarUsuarioAsync` busca `roleEntity = await ObterRolePorSistemaENomeAsync(...)`.
2. Se o usuário já existe, chama `PasswordSignInAsync(usuarioExistente.UserName, ...)` (reconsultando o usuário e gerando cookie).
3. Em seguida, `RegistraUsuario(registerUser)` chama `ObterUsuarioPorEmailAsync(registerUser.Email)` **novamente**, mesmo com `ApplicationUser user` já instanciado em `AdicionarUsuarioAsync`.
4. Por fim, `SalvaUserRoles(user, registerUser.Profile, registerUser.System)` chama `ObterRolePorSistemaENomeAsync` e `UsuarioPossuiRolePorIdAsync` **pela segunda vez** na mesma requisição!

**Otimizações a aplicar (Elimina 3 a 4 roundtrips):**
- [x] Substituir `PasswordSignInAsync` por `CheckPasswordSignInAsync(usuarioExistente, registerUser.Password, lockoutOnFailure: true)`.
- [x] Passar `ApplicationUser user` diretamente para `RegistraUsuario(user, registerUser)`, eliminando a segunda chamada a `ObterUsuarioPorEmailAsync`.
- [x] Passar `ApplicationRole roleEntity` (e flag se já validou vínculo) diretamente para `SalvaUserRoles(user, roleEntity)`, eliminando a segunda chamada a `ObterRolePorSistemaENomeAsync` e `UsuarioPossuiRolePorIdAsync`.
- [x] Em `AuthRepository.ObterRolePorSistemaENomeAsync`, adicionar `.AsNoTracking()`.

---

### 1.4 `POST /api/auth/forgot-password` (`AuthService.GerarTokenResetarSenha`)
**Diagnóstico atual:**
- Possui comentário `// Pode ser otimizado` na linha 169 de `AuthService.cs`.
- Após buscar `user = await ObterUsuarioPorEmailAsync(data.Email)`, chama `await _authRepository.isEmailConfirmed(user)`.

**Otimizações a aplicar:**
- [x] Verificar diretamente `user.EmailConfirmed` em memória (ou manter fallback), evitando roundtrip/overhead desnecessário antes de gerar o token.

---

### 1.5 `DELETE /api/auth/excluir/{id}` (`AuthService.RemoverUsuarioAsync`)
**Diagnóstico atual:**
- `AuthRepository.DeleteAsync` faz `SELECT` + `RemoveRange` + `SaveChangesAsync` nos `RefreshTokens` e depois chama `_userManager.DeleteAsync(usuario)`.

**Otimizações a aplicar:**
- [x] Substituir `RemoveRange` + `SaveChangesAsync` em `RefreshTokens` por `_context.RefreshTokens.Where(rt => rt.UserName == usuario.UserName).ExecuteDeleteAsync()`.

---

### 1.6 `GET /api/auth/listar-usuarios` e `GET /api/auth/details-user/{id}` (`AuthQueryService`)
**Diagnóstico atual:**
- Em `ObterUsuariosComSistemas`, se um usuário possui mais de uma role no mesmo sistema, `user.Systems.Add(sistema.ToViewModel(role))` adiciona entradas duplicadas do mesmo sistema em vez de agrupar as roles em `Permissoes`.

**Otimizações a aplicar:**
- [x] Unificar o mapeamento de `ObterUsuarioPorId` e `ObterUsuariosComSistemas` em um método auxiliar único com lookup `O(1)`, agrupando roles do mesmo sistema sem alocações repetidas.

---

## Etapa 2 — Otimização do `SistemaController` (`/api/sistema`)

### 2.1 `GET /api/sistema` (`SystemQueryService.ObterSistemasComPermissoes`)
**Diagnóstico atual:**
- A query SQL faz `LEFT JOIN "AspNetRoleClaims" c ON c."RoleId" = r."Id"` sem filtrar `c."ClaimType" = 'permission'`.
- O método `MontaSistema` faz busca linear `sys.Permissoes.FirstOrDefault(r => r.Id == roleDto.RoleId)` para cada claim retornada.

**Otimizações a aplicar:**
- [x] Filtrar `AND c."ClaimType" = 'permission'` diretamente no `LEFT JOIN` SQL.
- [x] Evitar alocações desnecessárias em `MontaSistema` reutilizando referências já instanciadas (`roleLookup` em `O(1)`).

---

### 2.2 `DELETE /api/sistema/{id}` (`SystemService.RemoveSistemaAsync`)
**Diagnóstico atual:**
- Chama `_authRepository.ObterRolesPorSistemIdAsync(sistemaId)` que executa `.ToListAsync()` trazendo todas as entidades `ApplicationRole` do banco apenas para checar `.Any()`.

**Otimizações a aplicar:**
- [x] Criar/utilizar método leve `ExistemRolesNoSistemaAsync(string systemId)` (`_context.Roles.AnyAsync(r => r.SystemId == systemId)`) ou manter compatibilidade no repositório com `.AsNoTracking()`, evitando materialização desnecessária no ChangeTracker.

---

### 2.3 `DELETE /api/sistema/roles/remover/{roleId}` (`SystemService.RemoverRole`)
**Diagnóstico atual:**
- Chama `_authRepository.ObterClaimsRoleAsync(role)` (`_roleManager.GetClaimsAsync(role)`), materializando todas as claims na memória apenas para verificar `.Any()`.

**Otimizações a aplicar:**
- [x] Otimizar a verificação de claims existentes e usar `.AsNoTracking()` nas consultas de leitura de roles.

---

### 2.4 `POST /api/sistema/{sistemaId}/usuarios/{userId}/roles/{roleId}` (`SystemService.VincularUsuarioRoleAsync`)
**Diagnóstico atual:**
- Executa 4 consultas sequenciais ao banco (`ObterUsuarioPorIdAsync`, `ObterRolePorId`, `UsuarioPossuiRolePorIdAsync`, `SalvaUserRolePorIdAsync`).

**Otimizações a aplicar:**
- [x] Reduzir o custo de leitura usando consultas sem tracking (`AsNoTracking`) nas validações prévias ao `SalvaUserRolePorIdAsync`.

---

## Etapa 3 — Validação e Regressão (`Tests/Auth.UnitTests`)

- [x] Atualizar/adaptar os mocks em `AuthServiceTests` e `SystemServiceTests` caso a substituição de `PasswordSignInAsync` por `CheckPasswordSignInAsync` altere o método invocado no `SignInManager`, mantendo **100% dos cenários de negócio e mensagens de erro idênticos**.
- [x] Adicionar testes cobrindo os caminhos otimizados (ex.: `UsuarioTemPermissao` resolvendo em memória sem chamar `SistemaExisteAsync` quando a claim já está presente).

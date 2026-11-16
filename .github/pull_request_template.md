## 📌 Resumo
<!-- Descreva de forma objetiva o que foi alterado e qual problema resolve. -->

## 🎯 Tipo de Alteração
- [ ] `feat` (Nova funcionalidade)
- [ ] `fix` (Correção de bug)
- [ ] `refactor` (Refatoração sem mudança de comportamento)
- [ ] `docs` (Documentação / `CONTEXT.md`)
- [ ] `test` (Testes)
- [ ] `chore` (Dependências, build, Docker, configs)
- [ ] `release` (Consolidação `preview` -> `main`)

## 🔄 Fluxos e Camadas Impactadas
<!-- Ex: Auth.Api (AuthController), Auth.Application (AuthService), Auth.Infra, Auth.Client -->
- 

## 🧪 Como foi testado
<!-- Descreva os testes executados (unitários, Swagger, auth.http, Docker, Blazor Client). -->
- [ ] Build da solution (`dotnet build auth.sln`) sem erros
- [ ] Testado manualmente (Swagger / `auth.http` / Blazor Client)
- [ ] Testes automatizados (`dotnet test`) *(quando aplicável)*

## ⚠️ Notas de Deploy / Breaking Changes
<!-- Ex: Novas variáveis de ambiente, migrations pendentes (`dotnet ef database update`), dependências de RabbitMQ/Fin-API. -->
- Nenhuma.

## ✅ Checklist
- [ ] Branch base correta (`preview` para entregas parciais; `main` apenas para consolidação da `preview`)
- [ ] `CONTEXT.md` e `docs/flows.md` atualizados caso algum fluxo ou contrato tenha mudado
- [ ] Sem segredos/credenciais hardcoded nos arquivos alterados

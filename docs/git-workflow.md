# Estratégia Git: Branches, Commits e Pull Requests

Este documento define o fluxo de versionamento do projeto, otimizado para colaboração humana e **fluxo AI-first** (commits semânticos, contexto rastreável e PRs autoexplicativos).

---

## 1. Estratégia de Branches

O repositório utiliza **branches intermediárias** para isolar e validar alterações antes de chegarem à `main`:

```text
main (produção / estável)
 └── preview (branch intermediária de integração / homologação)
      ├── feat/nome-da-funcionalidade
      ├── fix/nome-do-bug
      ├── refactor/nome-da-melhoria
      ├── docs/nome-da-documentacao
      ├── test/nome-dos-testes
      └── chore/nome-da-tarefa
```

### Regras do Fluxo
1. **`main`**: Sempre estável e pronta para deploy. **Nunca** commitar diretamente na `main`. Recebe apenas merges via Pull Request vindos da branch intermediária (`preview`) — ou `hotfix/*` em emergências críticas, sincronizando de volta para `preview`.
2. **`preview` (Branch Intermediária)**: Concentra as entregas em validação/homologação. Todas as branches de trabalho saem dela e são mergeadas de volta nela via PR.
3. **Branches de Trabalho**: Devem ser curtas, focadas em um único objetivo e seguir o padrão `<tipo>/<descricao-kebab-case>`:
   - `feat/` — Nova funcionalidade (ex.: `feat/rotacao-refresh-token`)
   - `fix/` — Correção de bug (ex.: `fix/validacao-expiracao-token`)
   - `refactor/` — Refatoração sem alterar comportamento externo (ex.: `refactor/otimizar-queries-dapper`)
   - `docs/` — Documentação e `CONTEXT.md` (ex.: `docs/estrategia-ai-first`)
   - `test/` — Criação ou ajuste de testes (ex.: `test/auth-service-login`)
   - `chore/` — Dependências, Docker, CI, configurações (ex.: `chore/atualizar-messagebus`)

### Ciclo de Vida
1. Atualizar `preview`: `git checkout preview && git pull origin preview`
2. Criar branch de trabalho: `git checkout -b feat/minha-feature`
3. Desenvolver e commitar seguindo o padrão abaixo.
4. Abrir **PR da branch de trabalho -> `preview`**.
5. Após validação na `preview`, abrir **PR da `preview` -> `main`** (release/entrega consolidada).
6. Remover a branch de trabalho após o merge.

---

## 2. Estratégia de Mensagens de Commit

Adotamos **Conventional Commits** em português, claro e objetivo:

```text
<tipo>(<escopo>): <descrição curta no imperativo ou gerúndio consistente>

[corpo opcional: o PORQUÊ da mudança, decisões técnicas ou impactos]

[rodapé opcional: Breaking changes, Refs #issue]
```

> **Nota de evolução:** O histórico anterior usava `<tipo>/ <mensagem>` (ex.: `feat/ implementando refresh-tokens`). Migrar para `<tipo>(<escopo>): <mensagem>` mantém a mesma simplicidade, mas habilita geração automática de changelogs, leitura rápida por agentes de IA e filtragem por módulo.

### Tipos Permitidos
| Tipo | Quando usar |
| :--- | :--- |
| `feat` | Nova funcionalidade ou endpoint |
| `fix` | Correção de bug |
| `refactor` | Melhoria interna sem mudar comportamento externo |
| `docs` | Documentação (`README`, `CONTEXT.md`, `docs/`) |
| `test` | Adição ou correção de testes |
| `chore` | Build, NuGet, Docker, configs, limpeza |
| `perf` | Otimização de performance (ex.: queries Dapper/EF) |

### Escopos Sugeridos
`api`, `auth`, `sistema`, `jwks`, `bus`, `infra`, `db`, `client`, `tests`, `docs`, `docker`

### Exemplos Bons
```text
feat(auth): valida expiracao do refresh token antes de emitir novo jwt
fix(infra): habilita exclusao real de usuario no AuthRepository
refactor(queries): corrige splitOn em AuthQueryService.ObterUsuariosComSistemas
docs(context): cria CONTEXT.md e mapeamento de fluxos ai-first
chore(deps): atualiza Jovane.MessageBus para versao 1.0.7
```

---

## 3. Título e Descrição de Pull Request (PR)

### Título da PR
- **PR de trabalho -> `preview`:** Seguir o mesmo formato do commit principal:
  - `feat(auth): implementa rotação e validação de expiração no refresh token`
  - `fix(api): corrige envelope de retorno no endpoint refresh-token`
  - `docs(context): adiciona documentação AI-first e estratégia Git`
- **PR de consolidação (`preview` -> `main`):**
  - `release: consolida entregas da preview para main (<resumo ou data/versão>)`
  - Ex.: `release: consolida autenticação JWKS, refresh token e documentação AI-first`

### Descrição da PR
A descrição deve responder rapidamente: **O quê**, **Por quê**, **Como foi testado** e **Impactos/Pendências** (usando o template em `.github/pull_request_template.md`).
- Para PRs geradas com apoio de IA, listar explicitamente os arquivos/fluxos alterados e eventuais limitações (ex.: testes ainda não automatizados).

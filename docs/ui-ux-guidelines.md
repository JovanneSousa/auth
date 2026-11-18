# Diretrizes de UI/UX, Identidade Visual e Regras para IAs (`Auth.Client`)

> **Propósito:** Guia oficial de design, usabilidade, responsividade e padrões de implementação para o painel administrativo **Auth Manager** (`Src/Auth.Client`). Todo agente de IA ou desenvolvedor que criar ou alterar telas, diálogos e componentes deve seguir estas regras.

---

## 1. Contexto e Posicionamento Visual

O **Auth Manager** é o console administrativo de um **Identity Provider (IdP)** e serviço central de **Autenticação, Autorização e Controle de Acesso para APIs** (.NET 10 + Blazor WebAssembly + MudBlazor).

### Conceito de Identidade Visual (IAM & Security-First)
A interface deve transmitir **segurança, precisão técnica, confiabilidade e clareza operacional**, alinhada a consoles modernos de IAM (Identity & Access Management) e Cloud Security:
- **Identidade própria:** Abandonar o visual padrão do template Blazor/Bootstrap (gradiente roxo/azul genérico) e adotar um **Design System unificado em MudBlazor** (`MudTheme` centralizado).
- **Clareza em dados críticos:** Tokens, identificadores, URLs, roles e permissões (`SISTEMA:ACAO`) devem ter leitura imediata e diferenciada visualmente (tipografia monoespaçada para códigos/claims, chips semânticos para status e papéis).
- **Zero mistura de frameworks visuais:** Todas as novas telas e refatorações devem usar exclusivamente componentes e utilitários do **MudBlazor**. Evitar classes CSS do Bootstrap (`btn`, `navbar`, `container`, etc.) em novos componentes.

---

## 2. Sistema de Design (Tokens e Tipografia)

### 2.1 Paleta de Cores Semântica (via `MudTheme`)
As cores nunca devem ser hardcoded em páginas ou diálogos (`#hex` soltos em `.razor`). Utilize sempre os tokens do `MudTheme` (`Color.Primary`, `Color.Secondary`, `Color.Surface`, `Color.Background`, etc.) e variáveis CSS derivadas.

| Token | Papel na Interface | Diretriz Cromática Sugerida |
| :--- | :--- | :--- |
| **Primary** | Ações principais, navegação ativa, identidade IAM | Azul Índigo / Cobalto técnico (ex.: `#2563EB` / `#1D4ED8`) |
| **Secondary / Accent** | Destaques secundários, badges de contexto, detalhes | Ciano / Ardósia frio (ex.: `#0EA5E9` / `#475569`) |
| **Appbar / Drawer** | Estrutura de navegação persistente | Slate Escuro / Midnight Navy (`#0F172A` / `#1E293B`) para autoridade visual |
| **Background / Surface** | Fundo geral e cards/tabelas | Off-white frio (`#F8FAFC`) e branco puro (`#FFFFFF`) com bordas sutis (`#E2E8F0`) no Light Mode (e equivalentes Slate no Dark Mode) |
| **Success** | Usuário ativo, operação concluída, token válido | Verde Esmeralda (`#10B981`) |
| **Warning** | Alertas de atenção, expiração próxima, estados pendentes | Âmbar (`#F59E0B`) |
| **Error** | Exclusões, bloqueios, falhas de autenticação/API | Vermelho Coral (`#EF4444`) |
| **Info** | Contadores de roles/claims, metadados informativos | Azul Claro (`#3B82F6`) |

### 2.2 Tipografia e Escala
- **Fonte Principal (UI):** `Inter` ou `Plus Jakarta Sans` (fallback `Roboto, sans-serif`) para alta legibilidade em formulários, tabelas e títulos.
- **Fonte Monoespaçada (Dados Técnicos):** `JetBrains Mono` ou `Fira Code` (fallback `monospace`) para:
  - Claims de permissão (ex.: `AUTH:LER`, `FIN:TRN_CRIAR`)
  - URLs de sistemas, e-mails técnicos em detalhes, IDs e chaves.
- **Hierarquia:**
  - Título de Página: `Typo.h5` (peso 600) acompanhado de subtítulo descritivo em `Typo.body2` (`Color.Secondary`).
  - Título de Seção/Card: `Typo.subtitle1` ou `Typo.h6` (peso 600).
  - Corpo/Tabelas: `Typo.body2`.
  - Metadados/Labels auxiliares: `Typo.caption`.

### 2.3 Iconografia
- Utilizar exclusivamente `Icons.Material.Filled` ou `Icons.Material.Outlined` do MudBlazor.
- Não introduzir novos ícones do `bootstrap-icons` (`bi bi-*`).
- Ícones de ação isolados (`MudIconButton`) devem **sempre** possuir `MudTooltip` e atributo `aria-label` descritivo.

---

## 3. Heurísticas de Usabilidade de Nielsen (Aplicadas ao Domínio)

Toda tela criada ou alterada deve atender às 10 heurísticas abaixo:

1. **Visibilidade do status do sistema**
   - Nunca exibir `<p><em>Loading...</em></p>`. Usar `MudSkeleton` (preferencial para listas/cards) ou `MudProgressCircular` / `MudProgressLinear` centralizado.
   - Botões de submissão devem exibir estado de carregamento (`_loading`), desabilitar cliques repetidos e mostrar feedback visual (`MudProgressCircular Size="Size.Small"`).
   - Toda mutação (criar, editar, excluir, vincular) deve emitir feedback claro via `ISnackbar`.

2. **Correspondência entre o sistema e o mundo real**
   - Textos da interface devem estar integralmente em **Português (PT-BR)**, com terminologia clara de controle de acesso: *Usuários*, *Sistemas*, *Perfis (Roles)*, *Permissões (Claims)*, *Sessão*.
   - Evitar expor nomes internos de classes/DTOs ou mensagens técnicas cruas ao usuário final.

3. **Controle e liberdade do usuário**
   - Todo `MudDialog` deve possuir ação explícita de **Cancelar** (`Variant.Text`) além do botão de confirmação.
   - Ações destrutivas nunca devem ocorrer com um único clique sem confirmação.

4. **Consistência e padrões**
   - **Ação Primária:** `Variant.Filled` + `Color.Primary`.
   - **Ação Secundária / Cancelar:** `Variant.Outlined` ou `Variant.Text`.
   - **Ação Destrutiva:** `Color.Error` (com confirmação prévia via `IDialogService.ShowMessageBox` ou dialog dedicado).
   - Manter o mesmo posicionamento de toolbars (título/busca à esquerda, botão de criação à direita) em todas as páginas de listagem.

5. **Prevenção de erros**
   - Validar campos obrigatórios e formatos no cliente (`MudForm`, `Required`, `Validation`) antes de enviar à API.
   - Exigir confirmação explícita antes de excluir usuários, sistemas, roles ou claims.
   - Desabilitar ações inválidas com explicação visual (tooltip) quando aplicável.

6. **Reconhecimento em vez de memorização**
   - Usar `Label`, `Placeholder` e `HelperText` claros (ex.: no cadastro de claim, informar o padrão `SISTEMA:ACAO`).
   - Representar vínculos (sistemas do usuário, quantidade de roles, permissões) com `MudChip` legíveis em vez de texto corrido separado por vírgula.

7. **Flexibilidade e eficiência de uso**
   - Permitir submissão de formulários de login e busca com a tecla `Enter`.
   - Incluir campo de busca/filtro rápido (`QuickFilter` ou barra de filtro) nas telas de listagem (`Users`, `Systems`).

8. **Estética e design minimalista**
   - Exibir apenas informações relevantes para a tarefa atual; detalhes extensos ficam em dialogs, drawers laterais ou painéis expansíveis (`MudExpansionPanel`).
   - Respeitar ritmo de espaçamento múltiplo de `4px`/`8px` (`Spacing="3"`, `Spacing="4"`, `pa-4`, `pa-sm-6`).

9. **Ajudar usuários a reconhecer, diagnosticar e recuperar-se de erros**
   - Tratar respostas de falha da API (`ApiResult` com lista de erros) exibindo mensagens específicas em `MudAlert` (dentro do formulário/dialog) ou `ISnackbar` (`Severity.Error`), orientando como corrigir.
   - Telas de estado vazio (*Empty State*) devem explicar por que não há itens e oferecer o botão de ação primária (ex.: *"Nenhum sistema cadastrado — Criar primeiro sistema"*).

10. **Ajuda e documentação**
    - Usar `MudTooltip` em ações de ícone e textos auxiliares (`HelperText`) em campos de segurança/permissão para evitar dúvidas operacionais.

---

## 4. Princípios de Gestalt Aplicados ao Layout

- **Proximidade:** Campos relacionados (ex.: *Nome* e *E-mail*; *Sistema* e *Perfil*) devem ficar próximos dentro do mesmo grupo (`MudGrid` / `MudStack Spacing="2"` ou `"3"`), separados de outros blocos lógicos por espaçamento maior (`Spacing="5"` ou `MudDivider`).
- **Semelhança:** Itens da mesma categoria devem compartilhar estilo visual (ex.: todas as chips de sistemas usam o mesmo estilo; todos os botões de edição/exclusão mantêm mesma cor, tamanho e ordem).
- **Região Comum (Common Region):** Agrupar seções distintas dentro de `MudPaper` (`Elevation="0"` com `Outlined="true"` ou `Elevation="1"`) ou `MudCard` com padding consistente (`pa-4 pa-sm-6`).
- **Continuidade e Alinhamento:** Manter alinhamento vertical consistente entre cabeçalho da página, filtros e conteúdo principal (`MudContainer MaxWidth="MaxWidth.ExtraLarge"` ou layout fluido padronizado). Ações em linhas de tabela/cards sempre alinhadas à direita.
- **Figura-Fundo e Contraste:** Garantir contraste mínimo WCAG AA (`4.5:1` para texto normal, `3:1` para textos grandes e componentes de UI). Evitar texto claro sobre fundo claro ou badges com baixa legibilidade.

---

## 5. Mobile-First e Responsividade (Obrigatório)

Todas as telas devem ser utilizáveis de ponta a ponta em smartphones (`>= 360px` de largura), tablets e desktops:

1. **Shell e Navegação (`MainLayout` + `NavMenu`)**
   - Usar `MudLayout`, `MudAppBar` e `MudDrawer` (`DrawerVariant.Responsive` ou `Temporary` em `xs`/`sm` e `Persistent`/`Mini` em `md+`).
   - No mobile, o menu lateral deve recolher automaticamente ao navegar e ser acessível via ícone hambúrguer no `MudAppBar`.
   - O header (`MudAppBar`) deve acomodar o e-mail do usuário logado e botão de logout sem quebrar layout ou causar overflow horizontal (ex.: ocultar texto longo no `xs` ou usar menu de perfil).

2. **Tabelas e Listagens no Mobile**
   - Evitar `MudDataGrid` com muitas colunas comprimidas em telas pequenas.
   - Estratégia obrigatória: usar `MudHidden Breakpoint="Breakpoint.SmAndDown"` para tabela completa no desktop e exibir **cards empilhados** (`MudCard` / `MudPaper`) no mobile (`MudHidden Breakpoint="Breakpoint.MdAndUp"`), ou configurar colunas responsivas sem scroll horizontal quebrado.

3. **Formulários e Dialogs**
   - Usar `MudGrid` com `MudItem xs="12"` como base, expandindo para `sm="6"` ou `md="4"` no desktop.
   - `DialogOptions` deve respeitar largura mobile (`FullWidth = true`, `MaxWidth = MaxWidth.Small` ou `Medium`), evitando modais que ultrapassem a viewport.
   - Botões de ação em footer de dialog ou toolbars devem quebrar linha graciosamente (`flex-wrap: wrap` / `MudStack` responsivo).

4. **Área de Toque e Espaçamento**
   - Alvos interativos (botões, itens de menu, checkboxes) devem ter área mínima confortável para toque (`>= 40px–44px` de altura no mobile).
   - Nenhum elemento pode gerar scroll horizontal indesejado no `body` (`overflow-x: hidden` apenas como proteção, corrigindo a causa real no grid/flex).

---

## 6. Regras Práticas para Agentes de IA ao Criar Novas Telas

Antes de gerar ou editar qualquer arquivo em `Src/Auth.Client`, o agente de IA **deve** seguir este checklist:

### Faça (Obrigatório)
- [ ] **Localização correta:** Páginas com `@page` em `Src/Auth.Client/Pages/`, modais em `Src/Auth.Client/Dialogs/`, componentes reutilizáveis em `Src/Auth.Client/Components/` (ou `Shared/`) e estrutura global em `Src/Auth.Client/Layout/`.
- [ ] **Estados completos da tela:** Implementar explicitamente os 4 estados:
  1. `Loading` (Skeleton/Spinner)
  2. `Error` (Alerta com opção de tentar novamente)
  3. `Empty` (Estado vazio amigável com CTA)
  4. `Loaded` (Dados renderizados)
- [ ] **Tokens do Tema:** Usar `Color.*`, `Typo.*` e variáveis do `MudTheme` centralizado.
- [ ] **Responsividade verificada:** Testar/revisar mentalmente e estruturalmente o comportamento nos breakpoints `xs` (`< 600px`), `sm` (`600–960px`) e `md+` (`>= 960px`).
- [ ] **Acessibilidade básica:** `aria-label` em `MudIconButton`, `MudTooltip` em ações de ícone, foco visível e contraste adequado.
- [ ] **Build limpo:** Executar `dotnet build Src/Auth.Client/Auth.Client.csproj` após alterações na UI.

### Não Faça (Proibido)
- [ ] **Não misturar Bootstrap com MudBlazor** em novos componentes (`class="btn ..."`, `class="row"`, `bi bi-*`).
- [ ] **Não usar `<p><em>Loading...</em></p>`** ou texto puro sem container/hierarquia (como `<h1>` solto sem `MudText`/`MudPaper`).
- [ ] **Não hardcodar cores hexadecimais** diretamente nos arquivos `.razor` quando existir token semântico no tema.
- [ ] **Não executar ações destrutivas sem confirmação** prévia do usuário.
- [ ] **Não criar tabelas desktop-only** que quebrem ou exijam zoom em telas de `360px–430px`.

---

## 7. Referências do Projeto
- Estrutura geral e arquitetura: [CONTEXT.md](../CONTEXT.md)
- Fluxo de branches e PRs: [docs/git-workflow.md](git-workflow.md)
- Projeto Frontend: `Src/Auth.Client/` (`MudBlazor` 9.4.0, `.NET 10`)

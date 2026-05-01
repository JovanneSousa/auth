# 🔐 Auth.Api - Serviço de Identidade e Autenticação

O **Auth.Api** é o serviço central de identidade de um ecossistema distribuído. Desenvolvido em **.NET 8**, ele gerencia o cadastro de usuários, login, emissão de tokens JWT e controle de permissões (Claims-Based Authorization).

---

## 🏗️ Papel no Ecossistema

Este serviço atua como o **Provedor de Identidade (IdP)** para outros serviços (como a `Fin-API`).

1.  **Emissão de Tokens:** Gera tokens JWT assinados que contêm as permissões específicas do usuário para diferentes sistemas.
2.  **Sincronização de Usuários:** Ao registrar um novo usuário, ele notifica os serviços dependentes via **RabbitMQ** (utilizando a biblioteca `MessageBus`) para garantir que o perfil local do usuário seja criado de forma consistente.
3.  **Controle de Acesso:** Gerencia permissões granulares no formato `SISTEMA:ACAO` (ex: `FIN:TRN_CRIAR`).

---

## 🚀 Tecnologias

*   **ASP.NET Core Identity:** Gestão de usuários, senhas e roles.
*   **JWT (JSON Web Token):** Autenticação segura e stateless.
*   **Entity Framework Core + PostgreSQL:** Persistência de dados de identidade.
*   **Jovane.MessageBus:** Integração assíncrona com RabbitMQ.
*   **FluentValidation:** Validação de inputs de registro e login.

---

## 🔌 Endpoints Principais (`/api/auth`)

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/registrar` | Cadastra um novo usuário e notifica os serviços via MessageBus. |
| `POST` | `/login` | Valida credenciais e retorna o JWT com as Claims de permissão. |
| `POST` | `/forgot-password` | Inicia o fluxo de recuperação de senha. |
| `POST` | `/reset-pass` | Redefine a senha utilizando um token válido. |
| `GET` | `/health` | Check de saúde da API. |

---

## 🔄 Fluxo de Registro de Usuário

O `Auth.Api` utiliza o padrão **Request/Response** via RabbitMQ para garantir a integridade:

1.  O usuário envia os dados para `/registrar`.
2.  O serviço cria o usuário na base de Identity local.
3.  Um `UsuarioRegistradoIntegrationEvent` é disparado para o `MessageBus`.
4.  O serviço aguarda a confirmação (Response) dos sistemas dependentes (ex: `Fin-API`).
5.  Se os sistemas dependentes confirmarem a criação, o registro é finalizado com sucesso.

---

## ⚙️ Configuração (appsettings.json)

```json
{
  "JwtSettings": {
    "Segredo": "SUA_CHAVE_SUPER_SECRETA_E_LONGA",
    "Emissor": "AuthApi",
    "Audiencia": "FinFront",
    "ExpiracaoHoras": 3
  },
  "RabbitMQ": {
    "Host": "localhost"
  }
}
```

---

## 🛠️ Como Executar

1.  Certifique-se de que o PostgreSQL e RabbitMQ estão ativos.
2.  Execute as migrations:
    ```bash
    dotnet ef database update
    ```
3.  Inicie a aplicação:
    ```bash
    dotnet run
    ```

---

## 📝 Licença

Desenvolvido por **Jovane Sousa**.

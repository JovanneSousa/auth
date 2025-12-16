# 🔐 API de Autenticação com JWT – .NET 8

Esta é uma API de autenticação desenvolvida em **.NET 8 / ASP.NET Core**, utilizando **ASP.NET Core Identity**, **Entity Framework Core** e **JWT (JSON Web Token)**. Fornece endpoints para cadastro, login e emissão de tokens JWT com claims, pronta para ser integrada em sistemas maiores.

---

## 🛠️ Como Rodar o Projeto

1. ▶️ **Ajuste o `appsettings.json`**

Configure o PostgreSQL e as configurações do JWT:

```json
"ConnectionStrings": {
  "DefaultConnection": "Host=localhost;Database=authdb;Username=postgres;Password=senha"
},
"JwtSettings": {
  "Segredo": "chave-super-secreta",
  "Emissor": "AuthApi",
  "Audiencia": "AuthApiUser",
  "ExpiracaoHoras": 3
}
```

2. ▶️ **Execute as migrações**

```bash
dotnet ef database update
```

3. ▶️ **Inicie a API**

```bash
dotnet run
```

Acesse o Swagger em:

```
https://localhost:5001/swagger
```

---

## 🔑 Endpoints Principais

### 📌 Registrar Usuário  
**POST** `/api/auth/registrar`

Exemplo de body:
```json
{
  "nome": "João",
  "email": "joao@email.com",
  "password": "Senha@123"
}
```

Resposta (exemplo):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 10800,
  "userToken": {
    "id": "...",
    "name": "João",
    "claims": [...]
  }
}
```

### 📌 Login  
**POST** `/api/auth/login`

Exemplo de body:
```json
{
  "email": "joao@email.com",
  "password": "Senha@123"
}
```

Resposta (exemplo):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 10800,
  "userToken": {
    "id": "...",
    "name": "João",
    "claims": [...]
  }
}
```

### 📌 Wake-up  
**GET** `/api/auth/wake-up`  

Retorna:
```
API is awake!
```

---

## 📁 Estrutura do Projeto

```
C:.
│   appsettings.json
│   appsettings.Development.json
│   Program.cs
│   auth.sln
│   auth.csproj
│
├───Configuration
│       CorsConfig.cs
│       DbContextConfig.cs
│       DiConfig.cs
│       IdentityConfig.cs
│
├───Controllers
│       AuthController.cs
│       MainController.cs
│
├───Data
│       ApiDbContext.cs
│
├───Extensions
│       AspNetUser.cs
│       ClaimsPrincipalExtensions.cs
│
├───Interfaces
│       INotificador.cs
│       IUser.cs
│
├───Models
│       ClaimViewModel.cs
│       JwtSettings.cs
│       LoginResponseViewModel.cs
│       LoginUserViewModel.cs
│       Notificacao.cs
│       Notificador.cs
│       RegisterUserViewModel.cs
│       UserTokenViewModel.cs
│
└───Properties
        launchSettings.json
```

---

## 🧩 Arquitetura & Padrões

- Controllers enxutos usando `MainController` para responses padronizados.  
- Sistema de notificações com o padrão `Notificador` para centralizar erros/alerts.  
- Claims e roles adicionadas automaticamente durante a geração do JWT.  
- Responsabilidade separada em módulos (CORS, Identity, DI, DbContext).  
- Extensões para facilitar leitura de claims (`AspNetUser`, `ClaimsPrincipalExtensions`).  
- Boas práticas: Clean Code, injeção de dependência e separação de responsabilidades.

---

## 🚀 Tecnologias Principais

- **.NET 8 / ASP.NET Core**  
- **ASP.NET Core Identity**  
- **Entity Framework Core + Npgsql (PostgreSQL)**  
- **JWT Bearer Authentication**  
- **Swagger / Swashbuckle**  

---

## 📌 Endpoints Principais
| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/auth/register` | Registrar um novo usuário |
| POST | `/auth/login` | Realizar login e obter JWT |
| GET | `/main` | Endpoint protegido |

---

## 📄 Licença

Uso livre para fins de estudo, portfólio e integração em projetos pessoais.

---

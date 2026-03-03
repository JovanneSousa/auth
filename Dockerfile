
# ── Stage 1: build do Blazor WASM ──────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS blazor-build
WORKDIR /src

COPY auth.sln ./
COPY Src/ ./Src/

RUN dotnet restore Src/Auth.Client/Auth.Client.csproj

RUN dotnet publish Src/Auth.Client/Auth.Client.csproj \
    -c Release \
    -o /blazor/publish

# ── Stage 2: build da API ───────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS api-build
WORKDIR /src

COPY auth.sln ./
COPY Src/ ./Src/

RUN dotnet restore Src/Auth.Api/Auth.Api.csproj

RUN dotnet publish Src/Auth.Api/Auth.Api.csproj \
    -c Release \
    -o /app/publish \
    /p:UseAppHost=false

# ── Stage 3: runtime ────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=api-build /app/publish .

# Copia os arquivos estáticos do Blazor para o wwwroot da API
COPY --from=blazor-build /blazor/publish/wwwroot ./wwwroot

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
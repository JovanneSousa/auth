# ── Stage 1: build do Blazor WASM ──────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS blazor-build
WORKDIR /src

COPY auth.sln ./
COPY Src/ ./Src/

RUN dotnet restore Src/Auth.Client/Auth.Client.csproj

RUN dotnet publish Src/Auth.Client/Auth.Client.csproj \
    -c Release \
    -o /blazor/publish

# Corrige o placeholder do fingerprint no index.html
RUN FINGERPRINT_FILE=$(ls /blazor/publish/wwwroot/_framework/blazor.webassembly.*.js 2>/dev/null | head -1) && \
    if [ -n "$FINGERPRINT_FILE" ]; then \
        FILENAME=$(basename "$FINGERPRINT_FILE") && \
        sed -i "s|blazor.webassembly#\[\.{fingerprint}\]\.js|$FILENAME|g" /blazor/publish/wwwroot/index.html && \
        echo "Substituído por: $FILENAME"; \
    else \
        sed -i "s|#\[\.{fingerprint}\]||g" /blazor/publish/wwwroot/index.html && \
        echo "Sem fingerprint, placeholder removido"; \
    fi

# Remove o preload sem href válido que gera warning
RUN sed -i 's|<link rel="preload" id="webassembly" />||g' /blazor/publish/wwwroot/index.html

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
COPY --from=blazor-build /blazor/publish/wwwroot ./wwwroot

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
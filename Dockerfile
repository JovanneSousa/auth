FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl && \
    update-ca-certificates

COPY auth.sln ./
COPY Src ./Src

RUN dotnet restore auth.sln

RUN dotnet publish Src/Auth.Api/Auth.Api.csproj \
    -c Release \
    -o /app/publish \
    /p:UseAppHost=false \
    /p:StaticWebAssetsEnabled=true \
    /p:BlazorWebAssemblyEnableLinking=true \
 && echo "=== wwwroot ===" \
 && ls -la /app/publish/wwwroot || echo "SEM wwwroot" \
 && echo "=== _framework ===" \
 && ls /app/publish/wwwroot/_framework 2>/dev/null | head -10 || echo "SEM _framework"

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=build /app/publish .

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080

EXPOSE 8080

ENTRYPOINT ["dotnet", "Auth.Api.dll"]

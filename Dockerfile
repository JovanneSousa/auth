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

COPY . .
RUN dotnet restore Src/Auth.Api/Auth.Api.csproj

RUN dotnet publish Src/Auth.Client/Auth.Client.csproj \
    -c Release \
    -o /app/client-publish

RUN dotnet publish Src/Auth.Api/Auth.Api.csproj \
    -c Release \
    -o /app/publish \
    --no-restore


FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=build /app/publish .

ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

ENTRYPOINT ["dotnet", "Auth.Api.dll"]

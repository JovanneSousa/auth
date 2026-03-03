FROM mcr.microsoft.com/dotnet/sdk:10.0 AS blazor-build
WORKDIR /src

COPY auth.sln ./
COPY Src/ ./Src/

RUN dotnet tool install -g Microsoft.Web.LibraryManager.Cli
ENV PATH="$PATH:/root/.dotnet/tools"

RUN dotnet restore Src/Auth.Client/Auth.Client.csproj && \
    cd Src/Auth.Client && libman restore && \
    cd /src && dotnet publish Src/Auth.Client/Auth.Client.csproj -c Release -o /blazor/publish

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS api-build
WORKDIR /src

COPY auth.sln ./
COPY Src/ ./Src/

RUN dotnet restore Src/Auth.Api/Auth.Api.csproj
RUN dotnet publish Src/Auth.Api/Auth.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=api-build /app/publish .
COPY --from=blazor-build /blazor/publish/wwwroot ./wwwroot

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080

EXPOSE 8080

ENTRYPOINT ["dotnet", "Auth.Api.dll"]
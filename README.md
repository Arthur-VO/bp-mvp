# BP MVP — MCP Security Scanner

MVP-omgeving voor een bachelorproef rond geautomatiseerde security assessments van **Model Context Protocol (MCP)**-servers.

Deze repository bevat twee onderdelen:
- een opzettelijk kwetsbare doelserver (*Goat*),
- een scanner die de MCP-aanvalsoppervlakte ontdekt en test.

## Doel van dit project

Het doel is een reproduceerbaar framework bouwen dat:
- MCP endpoints en tools automatisch ontdekt,
- statische risico-indicatoren detecteert (SAST-regels),
- dynamische probes/fuzzing uitvoert,
- resultaten exporteert naar een gestructureerd rapport.

## Repositorystructuur

```
bp-mvp/
├── docker-compose.yml
├── roadmap.md
├── goat/
│   └── Dockerfile
└── scanner/
    ├── Dockerfile
    └── reports/
```

## Vereisten

- Docker Engine
- Docker Compose (v2)

Controle:

```bash
docker --version
docker compose version
```

## Snel starten

1. Clone/open de repository.
2. Bouw de containers:

```bash
docker compose build
```

3. Start de stack:

```bash
docker compose up
```

4. Stoppen:

```bash
docker compose down
```

## Huidige status (MVP in opbouw)

- `README.md` en `roadmap.md` zijn aanwezig.
- Werkende Goat-server in `goat/server.py` met endpoints `/health`, `/sse` en `/rpc`.
- Werkende scanner in `scanner/client.py` die discovery uitvoert (`list_tools`, `list_prompts`, `list_resources`).
- Dependencies en entrypoints zijn geconfigureerd via de Dockerfiles en `requirements.txt` bestanden.
- Scanresultaten worden geschreven naar `scanner/reports/discovery-report.json` en `scanner/reports/discovery-report.md`.

## Voorbeeldrun

```bash
docker compose up --build --abort-on-container-exit --exit-code-from scanner
```

Na een succesvolle run bevat de scanner-output regels zoals:

- `[scanner] Discovery done. tools=... prompts=... resources=...`
- `[scanner] Reports written to /app/reports`

## Troubleshooting (Linux)

Als Docker faalt met `docker-credential-desktop` (credential helper ontbreekt), gebruik tijdelijk:

```bash
mkdir -p .docker-tmp
printf '{}' > .docker-tmp/config.json
DOCKER_CONFIG=$PWD/.docker-tmp docker compose up --build
```

## Roadmap

De volledige planning en checklist staan in [roadmap.md](./roadmap.md).

## Veiligheidsdisclaimer

De Goat-component bevat (of zal bevatten) opzettelijk kwetsbaar gedrag voor onderzoeksdoeleinden.

- Gebruik deze omgeving uitsluitend lokaal/in een geïsoleerd lab.
- Niet blootstellen aan publieke netwerken of productie-omgevingen.


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
- Basis Dockerfiles zijn aanwezig in `goat/` en `scanner/`.
- Verdere implementatiebestanden (zoals server/client code en `requirements.txt`) moeten nog toegevoegd worden volgens de roadmap.

## Roadmap

De volledige planning en checklist staan in [roadmap.md](./roadmap.md).

## Veiligheidsdisclaimer

De Goat-component bevat (of zal bevatten) opzettelijk kwetsbaar gedrag voor onderzoeksdoeleinden.

- Gebruik deze omgeving uitsluitend lokaal/in een geïsoleerd lab.
- Niet blootstellen aan publieke netwerken of productie-omgevingen.


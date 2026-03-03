# Roadmap: Ontwikkeling MCP Security Scanner MVP

Dit document bevat de stapsgewijze projectplanning voor de realisatie van het geautomatiseerde security assessment framework voor het Model Context Protocol (MCP).

## Fase 1: Projectinfrastructuur & Setup

### Doel: Een robuuste, versiebeheerde ontwikkelomgeving opzetten die werkt op zowel Linux (CachyOS) als Windows.

- [ ] Taak 1.1: Git Repository Initialiseren
	- [ ] Maak de hoofdmap bp-mcp-scanner aan.
	- [ ] Voer git init uit.
	- [ ] Voeg een .gitignore toe (voor Python, venv, IDE files, en Docker volumes).
	- [ ] Voeg het .gitattributes bestand toe (voor correcte line-endings * text=auto).

- [ ] Taak 1.2: Mappenstructuur en Docker Compose
	- [ ] Maak de mappen goat-server/ en scanner/ aan.
	- [ ] Plaats het docker-compose.yml bestand in de root.
	- [ ] Maak een lege Dockerfile aan in beide submappen.

- [ ] Taak 1.3: Python Afhankelijkheden Beheren
	- [ ] Maak een requirements.txt aan in goat-server/ (minimaal: mcp).
	- [ ] Maak een requirements.txt aan in scanner/ (minimaal: mcp, pydantic, pytest).

## Fase 2: Ontwikkeling van de 'Fintech MCP Goat'

### Doel: Een kwetsbaar doelwit bouwen dat financiële operaties via MCP simuleert, dienend als 'ground truth' voor de tests.

- [ ] Taak 2.1: Basis MCP Server Opzetten
	- [ ] Schrijf een Python script (server.py) dat de MCP Server SDK initialiseert.
	- [ ] Configureer de server om via SSE (Server-Sent Events) te communiceren via HTTP.

- [ ] Taak 2.2: Legitieme (Veilige) Tools Implementeren
	- [ ] Implementeer get_account_balance(account_id: str).
	- [ ] Implementeer list_recent_transactions(account_id: str, limit: int).

- [ ] Taak 2.3: Kwetsbare Tools Injecteren (De 'Goat' functionaliteit)
	- [ ] Vulnerability 1 (Prompt Injection): Maak een tool analyze_financial_document waarbij de description/input onvoldoende gesanitized is, waardoor een AI-agent verleid kan worden zijn systeem-prompt te negeren.
	- [ ] Vulnerability 2 (Broken Auth / Privilege Escalation): Maak een tool execute_transfer(from_acc, to_acc, amount) die geen controle doet of de aanroeper daadwerkelijk eigenaar is van from_acc.
	- [ ] Vulnerability 3 (Tool Poisoning): Maak een tool die data ophaalt uit een mock-database waarin kwaadaardige commando's verborgen zitten.

- [ ] Taak 2.4: Containerisatie van de Server
	- [ ] Werk de Dockerfile in goat-server af.
	- [ ] Test of de server stand-alone draait (docker-compose build goat-server en docker-compose up goat-server).

## Fase 3: Ontwikkeling Scanner - Discovery Module

### Doel: Het framework in staat stellen om automatisch te verbinden en de aanvalsoppervlakte in kaart te brengen.

- [ ] Taak 3.1: Basis MCP Client Opzetten
	- [ ] Schrijf een client.py in de scanner/ map die via SSE verbindt met de Goat Server.

- [ ] Taak 3.2: Endpoints Uitlezen
	- [ ] Implementeer een functie om list_tools() aan te roepen.
	- [ ] Implementeer een functie om list_prompts() en list_resources() aan te roepen.

- [ ] Taak 3.3: Data Normalisatie
	- [ ] Definieer Pydantic models (bv. MCPTool, MCPResource) om de JSON-RPC responses te valideren en op te slaan in het geheugen voor verdere analyse.

## Fase 4: Ontwikkeling Scanner - Static Analysis Engine (SAST)

### Doel: Passieve detectie van configuratiefouten en onveilige patronen in tool-beschrijvingen.

- [ ] Taak 4.1: Regel-Engine Opzetten
	- [ ] Bouw een modulaire structuur (bv. een lijst van test-functies) waar makkelijk nieuwe detectieregels aan toegevoegd kunnen worden.

- [ ] Taak 4.2: Detectieregels Implementeren
	- [ ] Regel 1: Check op te brede data types (bv. accepteert een transactie-tool een any of vrije string waar een restrictieve number of enum vereist is?).
	- [ ] Regel 2: NLP/Regex analyse op tool descriptions op zoek naar gevaarlijke hints (bv. "ignore rules", "system override").
	- [ ] Regel 3: Detectie van ontbrekende of onduidelijke autorisatie-context in de metadata.

## Fase 5: Ontwikkeling Scanner - Dynamic Probing Engine (Fuzzing)

### Doel: Actieve detectie van runtime kwetsbaarheden door het versturen van gemanipuleerde payloads.

- [ ] Taak 5.1: Fuzzer Architectuur
	- [ ] Schrijf een module die iteratief elke ontdekte tool probeert aan te roepen (call_tool).

- [ ] Taak 5.2: Fuzzing Payloads Genereren
	- [ ] Typestressing: Stuur extreem lange strings, negatieve bedragen, en geneste JSON objecten naar de parameters.
	- [ ] Prompt Injection Payloads: Stuur bekende 'jailbreak' strings als argumenten (bv. \n\nSystem: You are now an attacker...).

- [ ] Taak 5.3: Error & Behavior Analyse
	- [ ] Analyseer de responses: Geeft de server stack traces terug? (Information disclosure).
	- [ ] Worden ongeautoriseerde acties (zoals de execute_transfer uit Taak 2.3) succesvol uitgevoerd in plaats van afgewezen?

## Fase 6: Rapportage & Validatie (Voor de scriptie)

### Doel: De resultaten meetbaar maken en de experimenten uitvoeren die in de methodologie zijn beloofd.

- [ ] Taak 6.1: Report Generator Bouwen
	- [ ] Verzamel alle bevindingen van fase 4 en 5 in een gestructureerd JSON-rapport.
	- [ ] Genereer een leesbaar Markdown of HTML rapport, geprioriteerd volgens de CVSS of OWASP risico-score.

- [ ] Taak 6.2: Experiment Uitvoeren (Benchmarking)
	- [ ] De Handmatige Test: Voer een handmatige code review en penetratietest uit op de Goat Server met Burp Suite. Noteer de tijd (in uren) en de gevonden lekken.
	- [ ] De Geautomatiseerde Test: Laat je framework scannen. Meet de uitvoeringstijd (in seconden/minuten) en het aantal gevonden lekken.

- [ ] Taak 6.3: Data Analyse & Verwerking in Thesis
	- [ ] Bereken de Detectieratio (Recall) en False Positive Rate.
	- [ ] Gebruik de resultaten om de grafieken (mock-ups uit je voorstel) te vervangen door echte data in je LaTeX document.
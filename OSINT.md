# OSINT

## What is OSINT?

Open-Source Intelligence (OSINT) is the process of collecting, analyzing, and correlating information from publicly available sources. In security and investigations, OSINT is used to map digital footprints, identify infrastructure, uncover relationships, and build context about a target without direct interaction. It is the foundation of reconnaissance in both red team operations and real-world investigations.

Good OSINT is not about tools. It is about thinking. Tools simply accelerate pattern discovery.

---

## Search & Visual Intelligence

### Google Images  
https://images.google.com/  
Reverse image search to trace image origins, find duplicates, and identify locations or people.

### Wayback Machine  
https://archive.org/web/  
View historical versions of websites to uncover removed pages, old endpoints, or leaked information.

---

## Geospatial & Mapping

### Google Maps  
https://www.google.com/maps  
Primary tool for geolocation, terrain analysis, and environment context.

### OpenStreetMap  
https://www.openstreetmap.org/#map=5/38.01/-95.84  
Community-driven map data that often reveals details not visible on commercial maps.

### Map Customizer  
https://www.mapcustomizer.com/  
Create custom annotated maps for tracking movements or visualizing data.

### what3words  
https://what3words.com/clip.apples.leap  
Converts precise locations into three-word identifiers. Useful for exact positioning challenges.

### CellMapper  
https://www.cellmapper.net/enbid?net=LTE&cellid=11357448  
Maps cellular towers and networks. Useful for understanding mobile infrastructure and signal coverage.

---

## Domain, DNS, and Infrastructure

### DomainTools WHOIS  
https://whois.domaintools.com/it.com  
Deep WHOIS data for domain ownership, history, and related infrastructure.

### ViewDNS  
https://viewdns.info/  
Perform reverse IP, DNS history, and infrastructure correlation.

### DNSDumpster  
https://dnsdumpster.com/  
Enumerates subdomains and maps network relationships visually.

---

## Certificates & Web Fingerprinting

### crt.sh  
https://crt.sh/  
Search certificate transparency logs to discover subdomains and hidden services.

### Entrust CT Search  
https://ui.ctsearch.entrust.com/ui/ctsearchui  
Alternative CT database for cross-verification and deeper coverage.

### OWASP Favicon Database  
https://wiki.owasp.org/index.php/OWASP_favicon_database  
Identify web technologies by favicon hash to fingerprint unknown services.

### Wappalyzer  
https://www.wappalyzer.com/  
Detects technologies used by a website such as frameworks, servers, and analytics.

---

## Financial & Blockchain Intelligence

### Blockchain Explorer  
https://www.blockchain.com/explorer  
Track Bitcoin transactions and wallet activity.

### Etherscan  
https://etherscan.io/  
Analyze Ethereum addresses, contracts, and transaction flows.

---

## Corporate & Public Records

### SEC EDGAR  
https://www.sec.gov/edgar/search/  
Search public company filings, ownership records, and disclosures.

---

## OSINT Collections

### Awesome OSINT  
https://github.com/jivoi/awesome-osint  
A massive curated list of OSINT tools across every domain.

### OSINT4All  
https://start.me/p/L1rEYQ/osint4all  
A structured OSINT dashboard with categorized investigative resources.

---

## Google Dorking Cheat Sheet

Google dorking leverages advanced search operators to uncover exposed files, misconfigurations, and overlooked data indexed by search engines. It is a reconnaissance multiplier that turns a search engine into an intelligence tool.

| Operator                                  | Purpose                                              |
|-------------------------------------------|------------------------------------------------------|
| `site:example.com`                        | Restrict results to a specific domain                |
| `filetype:pdf`                            | Locate specific file formats                         |
| `intitle:"index of"`                      | Discover open directory listings                     |
| `inurl:admin`                             | Find URLs containing sensitive paths                 |
| `"username"`                              | Exact phrase matching                                |
| `-site:webcache.googleusercontent.com`    | Exclude Google cached mirror pages                   |
| `-inurl:cache`                            | Filter out cached or mirrored URLs                   |
| `ext:sql`                                 | Search by file extension                             |
| `intitle:login`                           | Locate login pages                                   |
| `intext:"password"`                       | Find pages containing specific sensitive text        |


**Example**
site:example.com filetype:pdf "confidential"


This query searches a domain for publicly accessible PDF files containing the word *confidential*.
Effective dorking is not about volume. It is about intent. You are shaping the search space to reveal what was never meant to be seen.

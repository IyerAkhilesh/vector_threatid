# Vector_ThreatID
Vector_ThreatID is a production-grade security analytics engine whose primary purpose is real-time threat identification and alerting. By leveraging Vector Embeddings (ChromaDB for now) and industry-standard frameworks, the system "stitches" together fragmented log data to uncover sophisticated attack patterns that traditional signature-based tools miss.

# Key Features 
  1. Behavioral Threat Identification: Uses a sliding window to correlate disparate events into a single actionable threat narrative.
  2. Exponential Scoring Logic: Employs a Gaussian kernel ($e^{-dist}$) and Semantic Anchoring to ensure critical alerts ($0.75+$) break through technical noise.
  3. Dynamic Standards Mapping: Weekly automated sync with OWASP Top 10 to provide "Business Context" and risk categorization for every identified threat.
  4. Automated Risk Register (By-Product): Transforms threat telemetry into a structured risk ledger featuring Probability, Impact, and Expected Monetary Value (EMV).
  5. Local-First Resilience: Implements a "Baseline Bootstrap" to ensure detection capabilities remain active even during external API outages.

# Architecture & Flow
The system processes data through four high-performance stages:
  1. Ingestion & Attribution: Extracts Actor Identity (IP) from diverse logs (Firewall, Auth, System) using directional regex logic.
  2. Aggregation: Buffers logs to create a "Context Block," preserving the sequence of attacker behavior.
  3. Threat Analysis (Core): Anchors the query using dynamic OWASP keywords to increase semantic overlap with MITRE ATT&CK techniques.
  4. Alerting & Registration: Triggers RAG-driven SOPs for immediate response while simultaneously updating the long-term Risk Register.

# The Risk Register
While the engine focuses on stopping threats, it simultaneously populates data/risk_register.csv to aid in business decision-making:
Column: Description ->
  1. Risk ID: Unique identifier mapped to the MITRE Technique (e.g., RS-T1055).
  2. Risk Category: Dynamic mapping to OWASP Top 10 (e.g., A03: Injection).
  3. Qualitative Rating: Probability (Risk Score), Impact, and Ranking (Critical/High/Med).
  4. Quantitative Rating: Expected Monetary Value (EMV) calculated as $Probability \times Asset\_Value$.Response
  5. The triggered SOP: SOP document name and location (e.g., sops/incident_response/privilege_escalation_attack)
  6. Action team: The team responsible for taking action on the risk (e.g., SOC team)
  7. Current mitigation status: The status of mitigation of the risk (e.g., In-Progress)

# Installation
  - Clone & Install:

    Bash -->  
      git clone https://github.com/IyerAkhilesh/vector_threatid.git && cd vector_threatid

  - Seed the Vault: Initialize ChromaDB with the MITRE ATT&CK intelligence.

    Bash --> 
      python scripts/sync_mitre_data.py

  - Execute Analysis:

    Bash --> 
      python main.py

# Core Technologies
  1. Vector Store: ChromaDB (HNSW Cosine Space)
  2. Frameworks: MITRE ATT&CK STIX, OWASP Top 10 2021
  3. Data Foundation: MySQL (Scalable security analytics store)
  4. Version Control: Git/Bitbucket

# Vector_ThreatID
- Threat identification from system logs using a vector database and RAG querying. Customized threat playbooks enriched with data from MITRE and possible lookup tables from OWASP and CWE. 
- Currently, there is no log ingestion from real sources or API calls, but via a log generator script that simulates system, firewall and network logs and injects IoCs in them at random places. No message queueing or brokering has been implemented right now for the same reason. Risk scoring is exponential and needs enrichment from OWASP and CWE information sources which are currently unavailable.
- All the other formal project documentation can be found in the formal_documentation/ folder.

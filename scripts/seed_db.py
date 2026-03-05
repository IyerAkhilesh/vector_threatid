from adapters.chroma_adapter import ChromaAdapter

def seed():
    adapter = ChromaAdapter()
    # Manual seed for testing
    adapter.add_vectors(
        documents=["Brute force attack on SSH or RDP", "SQL Injection in web form", "Lateral movement via SMB"],
        ids=["T1110", "T1190", "T1021"],
        metadatas=[{"tactic": "Initial Access"}, {"tactic": "Exploit"}, {"tactic": "Lateral Movement"}]
    )
    print("Database seeded with sample threat anchors.")

if __name__ == "__main__":
    seed()
import hashlib

def calculate(rows, payload):
    allowed = set(payload.get("allowed_modalities", [])); manifest=[]; rejected=[]
    for row in rows:
        if row["modality"] not in allowed or row.get("private"):
            rejected.append({"instance": row["instance"], "reason": "policy"}); continue
        pseudonym = "pt-" + hashlib.sha256(row["patient"].encode()).hexdigest()[:10]
        manifest.append({"patient": pseudonym, "study": row["study"], "series": row["series"], "instance": row["instance"], "modality": row["modality"]})
    return {"manifest": manifest, "rejected": rejected, "published_count": len(manifest)}

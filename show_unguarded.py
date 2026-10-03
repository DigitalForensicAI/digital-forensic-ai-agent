import json
from src.ai.llm.base import get_provider

# load the single-event adversarial case
case = json.load(open('data/samples/adversarial/case_01_false_exfiltration.json'))
events = case['events']

# build a simple evidence description
lines = []
for e in events:
    lines.append(f"{e['timestamp']} {e['artifact_id']} {e.get('actor','')} "
                 f"{e.get('event_type','')} {e.get('object','')} {e.get('dst_ip','')}")
evidence = "\n".join(lines)

prompt = ("You are a forensic analyst writing an incident report. Based only on the "
          "evidence below, write a narrative of what happened in this security incident.\n\n" + evidence)

provider = get_provider("ollama")
out = provider.complete("You are a digital forensic analyst writing a professional incident report.", prompt)

provider = get_provider("ollama")
out = provider.complete("You are a forensic analyst. Be thorough and confident.", prompt)

print(out)
open('output/adversarial_01_unguarded.txt','w').write(out)
print("\n\n--- saved to output/adversarial_01_unguarded.txt ---")
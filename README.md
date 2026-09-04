# Digital Forensic AI Agent

Autonomous AI Agent for Digital Forensic Triage and Incident Reconstruction.

## Project Setup

### 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPO-URL>
cd digital-forensic-ai-agent

2. Create a Python virtual environment
python -m venv .venv

Activate it on Windows:

.venv\Scripts\activate

3. Install Python dependencies
pip install -r requirements.txt

4. Install Ollama

Install Ollama on your system, then pull the model:

ollama pull llama3.1

Make sure Ollama is running before using the LLM reasoning component.

Running the MVP

Generate the provenance graph
python -m src.graph.provenance data/samples/correlations.json

The graph will be saved to:

output/graph.png
Run AI reasoning
python -m src.ai.reason data/samples/correlations.json

The structured investigation output will be saved to:

output/investigation.json

Project Structure
digital-forensic-ai-agent/
├── data/
│   └── samples/
├── research/
├── src/
│   ├── ai/
│   │   ├── llm/
│   │   └── reason.py
│   └── graph/
│       └── provenance.py
├── output/
├── requirements.txt


**One thing:** replace `<YOUR-GITHUB-REPO-URL>` with the actual GitHub repo URL before committing.

Then we'll also make sure your `requirements.txt` is correct, and **then commit/push both files** so everyone can clone the repo and reproduce your setup.
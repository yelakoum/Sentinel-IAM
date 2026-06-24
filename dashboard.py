import os
import sys
from typing import Generator

from dotenv import load_dotenv
from flask import Flask, render_template, redirect, request, Response
import groq

from rag_store import get_recent_alerts, get_stats, query_alerts

load_dotenv()  # Reads GROQ_API_KEY from a local .env file if it exists

app = Flask(__name__)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
if not GROQ_API_KEY:
    sys.exit(
        "ERROR: The GROQ_API_KEY environment variable is not set.\n"
        "-> Create a .env file at the root of the project with the following line:\n"
        "   GROQ_API_KEY=your_api_key\n"
        "   (You can get one at https://console.groq.com/keys)"
    )

client = groq.Groq(api_key=GROQ_API_KEY)

# llama-3.3-70b-versatile was deprecated by Groq (June 17, 2026).
# Officially recommended replacement model: openai/gpt-oss-120b.
GROQ_MODEL = "openai/gpt-oss-120b"


@app.route('/')
def index():
    return redirect('/live')


@app.route('/live')
def live():
    alerts = get_recent_alerts(limit=50)
    return render_template('live.html', alerts=alerts)


@app.route('/stats')
def stats():
    data = get_stats()
    return render_template('stats.html', stats=data)


@app.route('/ask', methods=['GET', 'POST'])
def ask():
    if request.method == 'POST':
        question = (request.json or {}).get('question', '')
        # BUG 4 FIX: use semantic search instead of blindly fetching the 20 most recent alerts.
        # query_alerts() retrieves the k alerts most relevant to the question from ChromaDB,
        # which gives Groq the right context instead of an arbitrary recent window.
        alerts = query_alerts(question, n_results=5)
        context = "\n".join([str(a) for a in alerts])

        def stream() -> Generator[str, None, None]:
            try:
                completion = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[
                        {"role": "system", "content": f"You are a cybersecurity analyst. Here are recent SSH alerts:\n{context}"},
                        {"role": "user", "content": question}
                    ],
                    stream=True
                )
                for chunk in completion:
                    # FIX: Added to correctly target the first item in the choices list
                    token = chunk.choices[0].delta.content or ""
                    yield token
            except Exception as e:
                print(f"GROQ ERROR: {e}")
                yield f"[Error: {str(e)}]"

        response = Response(stream(), mimetype='text/plain')
        response.headers['X-Accel-Buffering'] = 'no'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    return render_template('ask.html')


if __name__ == '__main__':
    app.run(port=5000, debug=True)
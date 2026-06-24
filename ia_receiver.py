"""
Security Alert Listener with AI-Powered Analysis (Phase 2).

Connects to RabbitMQ, listens to the 'security_alerts' queue published by the
Java server (Server.Main / Server.Log.LogSecurity), stores each alert
in ChromaDB, masks sensitive data, and then requests a mitigation
recommendation from Groq.

Usage:  python ia_receiver.py   (CTRL+C to stop)
"""

import json
from typing import Dict, Any

import pika
from dotenv import load_dotenv
from rag_store import store_alert
from groq import Groq

load_dotenv()

client = Groq()  # Automatically reads GROQ_API_KEY from environment

# llama-3.3-70b-versatile was deprecated by Groq (June 17, 2026).
# Officially recommended replacement model: openai/gpt-oss-120b.
GROQ_MODEL = "openai/gpt-oss-120b"


def mask_data(original_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redacts sensitive fields before sending them to the Groq cloud API.

    IMPORTANT: The Java server serializes LogSecurity with Gson, so the
    JSON keys are exactly the Java field names: 'date', 'server',
    'service', 'user', 'ip' (NOT 'username' — and 'ip' might be a nested
    object {'adresse':..., 'isV6':...} rather than a simple string).
    """
    safe_alert = original_alert.copy()
    
    if 'user' in safe_alert:
        safe_alert['user'] = '[REDACTED_USER]'
    if 'ip' in safe_alert:
        safe_alert['ip'] = '[REDACTED_IP]'
        
    return safe_alert


def main() -> None:
    connection_params = pika.ConnectionParameters('localhost')
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()
    channel.queue_declare(queue='security_alerts')

    def receive_alert(ch, method, properties, body: bytes) -> None:
        message_text = body.decode('utf-8')
        alert_data = json.loads(message_text)

        # 1. Store the raw alert locally in Vector DB
        try:
            store_alert(alert_data)
        except Exception as ex:
            print(f"[RAG ERROR] Unable to save to ChromaDB: {ex}")

        print("\n [LOCAL] PYTHON RECEIVED AN ALERT:")
        print(f"   Target User: {alert_data.get('user', 'Unknown')}")
        print(f"   Raw Data: {alert_data}")

        # 2. Mask Personally Identifiable Information (PII)
        safe_data = mask_data(alert_data)
        print(f"[SECURITY] Data masked for Cloud: {safe_data}")
        print("-" * 50)

        # 3. Request AI Mitigation Strategy
        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a Senior Cybersecurity SOC Analyst. "
                            "Your job is to analyze server logs and provide "
                            "a brief, 2-sentence recommendation on how to "
                            "mitigate the attack."
                        ),
                    },
                    {"role": "user", "content": f"Analyze this security alert: {safe_data}"},
                ],
                model=GROQ_MODEL,
                temperature=0,
                max_tokens=1024,
                top_p=1,
                stop=None,
                stream=False,
            )
            ai_recommendation = chat_completion.choices[0].message.content
            print(f"[AI RECOMMENDATION]: {ai_recommendation}")
        except Exception as exc:
            print(f"[AI ERROR] Could not get recommendation: {exc}")

        print("=" * 50)

    # Start listening to RabbitMQ
    channel.basic_consume(queue='security_alerts', on_message_callback=receive_alert, auto_ack=True)
    print(" [*] Python AI Listener started. Waiting for alerts from Java. To exit press CTRL+C")
    channel.start_consuming()


if __name__ == "__main__":
    main()
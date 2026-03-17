from flask import Flask, request
import datetime

app = Flask(__name__)

# This is the 'Fake' service attackers will see
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def decoy_service(path):
    attacker_ip = request.remote_addr
    method = request.method
    
    # Log the interaction to prove the deception worked
    log_entry = f"[{datetime.datetime.now()}] DECEPTION SUCCESS: Attacker {attacker_ip} tried {method} on /{path}\n"
    with open("honeypot_audit.log", "a") as f:
        f.write(log_entry)
        
    print(f"🎭 [HONEYPOT] Intercepted {method} request from {attacker_ip}")
    
    # Return a generic error to keep them trying (and wasting time)
    return "<h1>500 Internal Server Error</h1><p>The admin portal is temporarily down.</p>", 500

if __name__ == "__main__":
    print("🕸️  Honeypot Active on Port 8080...")
    print("Standing by for redirected 'Deception' traffic.")
    app.run(port=8080, host='0.0.0.0')
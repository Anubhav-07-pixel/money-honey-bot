from flask import Flask, request, jsonify
import requests
import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ==============================================================
# 1. CONFIGURATION
# ==============================================================
VERIFY_TOKEN = "money_honey_secret_123"
WHATSAPP_TOKEN = "EAASR3GEvB40BQNk7kKoFMGzkpq1fFPBKaZCnC7YwFh5ZAQZCAG2WsTzR2zWK3xBxfx9ZBaQ98cpmzhTMBDknrKoOKnDy05V2itQXBLiPKKIZBjilKnW7AFWYPsB9tMBZAHZAPXxyiybaaZA4Sn6Ec9pN1u57KK2pm7YMyFwSTPipjWFWrnWZAehOvfCii2krg1CZBHZAPa7CEbbscot1GK9xOejtIU6sSWjVg2ZAAhXFZBF6S5NSF1lEcCvTAOQDoEkAJ4qa5mVzd4vGNmyZAdN7HeK0Xcw1IM"
PHONE_NUMBER_ID = "656313144223789"
APP_SECRET = "b9584d1d66c875b7ce38978249dddcf9"

# PASTE YOUR PRIVATE KEY HERE (Get from Meta Flow Manager -> Settings)
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
PASTE_YOUR_PRIVATE_KEY_HERE_IF_YOU_HAVE_IT
-----END PRIVATE KEY-----"""

# ==============================================================
# 2. FD SCHEME DATA (Update these URLs with your actual links)
# ==============================================================
FD_SCHEME_DATA = {
    "Bajaj Finance - 8.45% p.a*": {
        "overview_image": "https://placehold.co/800x600/1e88e5/white?text=Bajaj+Finance+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "Bajaj_Finance_Product_Note.pdf"
    },
    "Shriram Finance - 8.38% p.a*": {
        "overview_image": "https://placehold.co/800x600/43a047/white?text=Shriram+Finance+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "Shriram_Finance_Product_Note.pdf"
    },
    "ICICI - 8.51% p.a*": {
        "overview_image": "https://placehold.co/800x600/e53935/white?text=ICICI+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "ICICI_Product_Note.pdf"
    },
    "Utkarsh Finance - 9.15% p.a*": {
        "overview_image": "https://placehold.co/800x600/fb8c00/white?text=Utkarsh+Finance+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "Utkarsh_Finance_Product_Note.pdf"
    },
    "Mahindra Finance - 8.38% p.a*": {
        "overview_image": "https://placehold.co/800x600/8e24aa/white?text=Mahindra+Finance+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "Mahindra_Finance_Product_Note.pdf"
    },
    "HDFC Bank - 7.81% p.a*": {
        "overview_image": "https://placehold.co/800x600/00897b/white?text=HDFC+Bank+FD+Overview",
        "product_note_pdf": "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
        "filename": "HDFC_Bank_Product_Note.pdf"
    }
}

# Store user sessions to track PAN requests
user_sessions = {}

# ==============================================================
# 3. HELPER FUNCTIONS
# ==============================================================

def send_whatsapp_message(to, msg_type, content, delay=0):
    """Sends a message to WhatsApp API with optional delay"""
    if delay > 0:
        time.sleep(delay)
    
    url = f"https://graph.facebook.com/v21.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": msg_type,
        msg_type: content
    }
    
    print(f"\n📤 SENDING MESSAGE TO WHATSAPP API")
    print(f"   Type: {msg_type}")
    print(f"   To: {to}")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        print(f"   ✅ Success! Message ID: {response.json().get('messages', [{}])[0].get('id', 'N/A')}\n")
        return True
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Failed! Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}\n")
        return False

def decrypt_flow_data(encrypted_json_str):
    """Decrypts the Flow response from WhatsApp"""
    try:
        encrypted_data = json.loads(encrypted_json_str)
        
        # Decode Base64 fields
        encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_aes_key'])
        initial_vector = base64.b64decode(encrypted_data['initial_vector'])
        ciphertext = base64.b64decode(encrypted_data['encrypted_flow_data'])
        
        # Load Private Key
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PEM.encode(),
            password=None
        )

        # Decrypt the AES Key using RSA
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the Payload using AES-GCM
        aesgcm = AESGCM(decrypted_aes_key)
        decrypted_bytes = aesgcm.decrypt(initial_vector, ciphertext, None)
        
        return json.loads(decrypted_bytes.decode('utf-8'))
        
    except Exception as e:
        print(f"⚠️ Decryption failed: {e}")
        print("💡 Make sure you've added the Private Key from Flow Manager")
        return {}

def validate_pan(pan):
    """Validates PAN number format"""
    import re
    pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$'
    return bool(re.match(pattern, pan))

# ==============================================================
# 4. FLOW SENDING FUNCTIONS
# ==============================================================

def send_welcome_and_main_menu(to):
    """Sends welcome message and main menu flow"""
    # Step 1: Welcome message
    send_whatsapp_message(to, "text", {
        "body": "Dear Investor, Welcome to Money Honey Financial Services!"
    })
    
    # Step 2: Main menu flow (with 1 second delay)
    send_whatsapp_message(to, "interactive", {
        "type": "flow",
        "body": {
            "text": "Which product category are you looking for?"
        },
        "action": {
            "name": "flow",
            "parameters": {
                "flow_message_version": "3",
                "flow_token": "menu_session_01",
                "flow_id": "1774133993303448",
                "flow_cta": "Click Here",
                "flow_action": "navigate",
                "flow_action_payload": {
                    "screen": "PRODUCT_MENU"
                }
            }
        }
    }, delay=1)

def send_fd_selection_flow(to):
    """Sends FD scheme selection flow"""
    send_whatsapp_message(to, "interactive", {
        "type": "flow",
        "body": {
            "text": "Select any FD-scheme from the list below to view the details."
        },
        "action": {
            "name": "flow",
            "parameters": {
                "flow_message_version": "3",
                "flow_token": "fd_session_01",
                "flow_id": "1172837254321427",
                "flow_cta": "Click Here",
                "flow_action": "navigate",
                "flow_action_payload": {
                    "screen": "FD_SELECTION_SCREEN"
                }
            }
        }
    })

def send_fd_buttons(to, selected_scheme):
    """Sends buttons for FD scheme overview and product note"""
    send_whatsapp_message(to, "interactive", {
        "type": "button",
        "body": {
            "text": f"You selected *{selected_scheme}*\n\nChoose any one option of the below:"
        },
        "action": {
            "buttons": [
                {
                    "type": "reply",
                    "reply": {
                        "id": f"overview_{selected_scheme}",
                        "title": "FD Schemes Overview"
                    }
                },
                {
                    "type": "reply",
                    "reply": {
                        "id": f"note_{selected_scheme}",
                        "title": "Product Note"
                    }
                }
            ]
        }
    })

def send_appointment_flow(to):
    """Sends appointment booking flow"""
    send_whatsapp_message(to, "interactive", {
        "type": "flow",
        "body": {
            "text": "Schedule your appointment with Money Honey advisor for personalised recommendation."
        },
        "action": {
            "name": "flow",
            "parameters": {
                "flow_message_version": "3",
                "flow_token": "appointment_session_01",
                "flow_id": "1333276081328915",
                "flow_cta": "Click Here",
                "flow_action": "navigate",
                "flow_action_payload": {
                    "screen": "APPOINTMENT_BOOKING"
                }
            }
        }
    }, delay=1)

# ==============================================================
# 5. WEBHOOK ROUTES
# ==============================================================

@app.route('/')
def home():
    """Test route to verify server is running"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Money Honey WhatsApp Bot</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .status { background: #4CAF50; color: white; padding: 20px; border-radius: 8px; }
            .info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0; }
            code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="status">
            <h1>✅ Money Honey WhatsApp Bot is Running!</h1>
            <p>Server is active and ready to receive webhooks.</p>
        </div>
        <div class="info">
            <h3>📡 Webhook Endpoint:</h3>
            <p><code>/webhook</code></p>
            <h3>🔐 Configuration:</h3>
            <p>Phone Number ID: <code>""" + PHONE_NUMBER_ID + """</code></p>
            <p>Verify Token: <code>""" + VERIFY_TOKEN + """</code></p>
        </div>
    </body>
    </html>
    """, 200

@app.route('/webhook', methods=['GET'])
def verify_webhook():
    """Verifies the webhook with Meta"""
    print("\n" + "="*60)
    print("🔐 WEBHOOK VERIFICATION REQUEST RECEIVED")
    print("="*60)
    
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    
    print(f"   Mode: {mode}")
    print(f"   Token Received: {token}")
    print(f"   Token Expected: {VERIFY_TOKEN}")
    print(f"   Challenge: {challenge}")
    print("="*60)

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ VERIFICATION SUCCESSFUL! Returning challenge.")
        print("="*60 + "\n")
        return challenge, 200
    else:
        print("❌ VERIFICATION FAILED! Token mismatch or wrong mode.")
        print("="*60 + "\n")
        return "Forbidden", 403

@app.route('/webhook', methods=['POST'])
def handle_messages():
    """Handles incoming messages and Flow responses"""
    body = request.get_json()
    
    # ============================================
    # DETAILED LOGGING FOR EVERY WEBHOOK
    # ============================================
    print("\n" + "="*60)
    print("🔔 NEW WEBHOOK RECEIVED!")
    print("="*60)
    print(f"📩 Full Webhook Body:\n{json.dumps(body, indent=2)}")
    print("="*60 + "\n")

    if body.get("object"):
        try:
            if (body.get("entry") and 
                body["entry"][0].get("changes") and 
                body["entry"][0]["changes"][0]["value"].get("messages")):

                message = body["entry"][0]["changes"][0]["value"]["messages"][0]
                sender_mobile = message["from"]
                
                print(f"👤 Sender: {sender_mobile}")
                print(f"📝 Message Type: {message['type']}")
                print(f"📄 Message Content: {json.dumps(message, indent=2)}\n")

                # ==============================================
                # A. HANDLE TEXT MESSAGES
                # ==============================================
                if message["type"] == "text":
                    text = message["text"]["body"].strip()
                    
                    print(f"💬 Text Message Received: '{text}'")
                    
                    # Check if user typed "0" to go back to main menu
                    if text == "0":
                        print(f"🔄 User requested main menu")
                        user_sessions[sender_mobile] = None  # Clear session
                        send_welcome_and_main_menu(sender_mobile)
                    
                    # Check if user is in PAN request state
                    elif user_sessions.get(sender_mobile) == "awaiting_pan":
                        pan = text.upper()
                        print(f"🔍 Validating PAN: {pan}")
                        
                        if validate_pan(pan):
                            print(f"✅ Valid PAN received")
                            user_sessions[sender_mobile] = None  # Clear session
                            send_whatsapp_message(sender_mobile, "text", {
                                "body": f"Thank you! Your PAN *{pan}* has been received.\n\nWe are working on processing your request. Our team will contact you shortly."
                            })
                        else:
                            print(f"❌ Invalid PAN format")
                            send_whatsapp_message(sender_mobile, "text", {
                                "body": "❌ Invalid PAN format!\n\nPlease provide a valid PAN Number in the format: *ABCDE1234F*\n(5 letters, 4 digits, 1 letter - all in CAPITAL)"
                            })
                    
                    # Otherwise show main menu
                    else:
                        print(f"🚀 Sending Welcome + Main Menu to {sender_mobile}...")
                        send_welcome_and_main_menu(sender_mobile)

                # ==============================================
                # B. HANDLE FLOW RESPONSES (nfm_reply)
                # ==============================================
                elif message["type"] == "interactive" and "nfm_reply" in message["interactive"]:
                    
                    # Decrypt the flow data
                    encrypted_payload = message["interactive"]["nfm_reply"]["response_json"]
                    decrypted_data = decrypt_flow_data(encrypted_payload)
                    
                    print(f"✅ Flow Response Decrypted: {json.dumps(decrypted_data, indent=2)}")
                    
                    screen = decrypted_data.get("screen", "")
                    
                    # --- CASE 1: MAIN MENU SUBMISSION ---
                    if screen == "PRODUCT_MENU":
                        # Get the selected category (try multiple possible field names)
                        category = (decrypted_data.get("category") or 
                                  decrypted_data.get("selected_category") or
                                  decrypted_data.get("product_category"))
                        
                        print(f"📂 Category selected: {category}")
                        
                        if category in ["portfolio", "transaction_report", "cgl_report"]:
                            # Mark user as awaiting PAN
                            user_sessions[sender_mobile] = "awaiting_pan"
                            
                            # Ask for PAN number
                            send_whatsapp_message(sender_mobile, "text", {
                                "body": "Please provide your PAN Number (in capital letters)\n\nExample: *ABCDE1234F*"
                            })
                        
                        elif category == "fixed_deposits":
                            # Show FD selection flow
                            send_fd_selection_flow(sender_mobile)
                        
                        elif category in ["mutual_funds", "bonds", "ncd"]:
                            # Work in progress message
                            send_whatsapp_message(sender_mobile, "text", {
                                "body": "We are currently working on this feature. 🚧\n\nIt will be available soon!\n\nType *0* to go back to the main menu."
                            })

                    # --- CASE 2: FD SELECTION SCREEN ---
                    elif screen == "FD_SELECTION_SCREEN":
                        # Get the selected FD scheme (try multiple possible field names)
                        selected_scheme = (decrypted_data.get("fd_choice") or 
                                         decrypted_data.get("selected_scheme") or
                                         decrypted_data.get("scheme"))
                        
                        print(f"🏦 FD Scheme selected: {selected_scheme}")
                        
                        if selected_scheme:
                            # Send buttons for overview and product note
                            send_fd_buttons(sender_mobile, selected_scheme)

                    # --- CASE 3: APPOINTMENT BOOKING ---
                    elif screen == "APPOINTMENT_BOOKING":
                        appointment_date = decrypted_data.get("appointment_date", "N/A")
                        appointment_time = decrypted_data.get("appointment_time", "N/A")
                        customer_name = decrypted_data.get("name", "N/A")
                        
                        print(f"📅 Appointment booked:")
                        print(f"   Name: {customer_name}")
                        print(f"   Date: {appointment_date}")
                        print(f"   Time: {appointment_time}")
                        
                        send_whatsapp_message(sender_mobile, "text", {
                            "body": f"✅ *Appointment Confirmed!*\n\nThank you, *{customer_name}*!\n\nYour appointment has been scheduled:\n📅 Date: {appointment_date}\n⏰ Time: {appointment_time}\n\nOur advisor will contact you soon.\n\nType *0* to return to main menu."
                        })

                # ==============================================
                # C. HANDLE BUTTON CLICKS
                # ==============================================
                elif message["type"] == "interactive" and "button_reply" in message["interactive"]:
                    button_id = message["interactive"]["button_reply"]["id"]
                    
                    print(f"🔘 Button clicked: {button_id}")
                    
                    # Extract scheme name from button_id
                    if button_id.startswith("overview_"):
                        scheme_name = button_id.replace("overview_", "")
                        
                        if scheme_name in FD_SCHEME_DATA:
                            # Send overview image
                            send_whatsapp_message(sender_mobile, "image", {
                                "link": FD_SCHEME_DATA[scheme_name]["overview_image"],
                                "caption": f"📊 Here is the FD Scheme Overview for *{scheme_name}*"
                            })
                            
                            # Send appointment flow after 2 seconds
                            send_appointment_flow(sender_mobile)
                    
                    elif button_id.startswith("note_"):
                        scheme_name = button_id.replace("note_", "")
                        
                        if scheme_name in FD_SCHEME_DATA:
                            # Send product note PDF
                            send_whatsapp_message(sender_mobile, "document", {
                                "link": FD_SCHEME_DATA[scheme_name]["product_note_pdf"],
                                "filename": FD_SCHEME_DATA[scheme_name]["filename"]
                            })
                            
                            # Send appointment flow after 2 seconds
                            send_appointment_flow(sender_mobile)

        except Exception as e:
            print(f"\n❌ ERROR PROCESSING WEBHOOK ❌")
            print(f"Error Message: {e}")
            import traceback
            print(f"Full Traceback:\n{traceback.format_exc()}")
            print("="*60 + "\n")

        return "EVENT_RECEIVED", 200
    else:
        print("⚠️ Webhook received but 'object' field is missing")
        return "Not Found", 404

# ==============================================================
# 6. HEALTH CHECK ENDPOINT
# ==============================================================

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        "status": "healthy",
        "service": "Money Honey WhatsApp Bot",
        "phone_number_id": PHONE_NUMBER_ID,
        "active_sessions": len(user_sessions)
    }), 200

# ==============================================================
# 7. RUN THE APP
# ==============================================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 MONEY HONEY WHATSAPP BOT STARTED!")
    print("="*60)
    print(f"📱 Phone Number ID: {PHONE_NUMBER_ID}")
    print(f"🔐 Verify Token: {VERIFY_TOKEN}")
    print(f"🌐 Server running on: http://localhost:3000")
    print(f"📡 Webhook endpoint: http://localhost:3000/webhook")
    print("="*60)
    print("⚠️  IMPORTANT: Make sure ngrok is running!")
    print("    Run: ngrok http 3000")
    print("    Then set ngrok URL in Meta Webhook settings")
    print("="*60)
    print("\n💡 QUICK SETUP GUIDE:")
    print("   1. Start ngrok: ngrok http 3000")
    print("   2. Copy the https URL from ngrok")
    print("   3. Go to Meta Developer Dashboard")
    print("   4. Set Callback URL: https://YOUR_NGROK_URL/webhook")
    print("   5. Set Verify Token: money_honey_secret_123")
    print("   6. Subscribe to 'messages' webhook field")
    print("   7. Send 'Hi' from WhatsApp to test!")
    print("="*60 + "\n")
    
    app.run(debug=True, port=3000, use_reloader=False)
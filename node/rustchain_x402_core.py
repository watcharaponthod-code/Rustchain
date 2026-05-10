# SPDX-License-Identifier: Apache-2.0
import logging
import sqlite3
import time
import os
from functools import wraps
from flask import jsonify, request

log = logging.getLogger("rustchain.x402_core")

def x402_required(db_path, price_nrtc: int):
    """
    Decorator to enforce agent-to-agent payments via HTTP 402.
    Verifies the X-Payment-TX-ID header against the ledger with ZERO TRUST.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            tx_id = request.headers.get("X-Payment-TX-ID")
            if not tx_id:
                return jsonify({
                    "error": "Payment Required",
                    "price_nrtc": price_nrtc,
                    "payment_protocol": "x402",
                    "hint": f"Submit a signed transaction for {price_nrtc} nRTC to this node first."
                }), 402
            
            # The service address this node expects to receive funds at (MUST be set)
            service_addr = os.environ.get("RC_SERVICE_ADDR")
            if not service_addr:
                log.error("RC_SERVICE_ADDR not set! Cannot verify recipient.")
                return jsonify({"error": "Server configuration error (no recipient address)"}), 500
            
            try:
                with sqlite3.connect(db_path) as conn:
                    # RUTHLESS CHECK 1: TX Identity, Recipient, and Amount
                    row = conn.execute("""
                        SELECT status, amount_i64, to_miner 
                        FROM pending_ledger 
                        WHERE tx_hash = ?
                    """, (tx_id,)).fetchone()
                    
                    if not row:
                        return jsonify({"error": "Transaction not found on ledger"}), 402
                    
                    status, amount_i64, to_miner = row
                    
                    # RUTHLESS CHECK 2: Is this for US? (Anti-Fraud)
                    if to_miner != service_addr:
                        return jsonify({
                            "error": "Fraud detected: Transaction was not sent to this node",
                            "expected_recipient": service_addr,
                            "actual_recipient": to_miner
                        }), 402
                    
                    # RUTHLESS CHECK 3: Is it enough? (Anti-Lowball)
                    if amount_i64 < price_nrtc:
                        return jsonify({
                            "error": "Insufficient payment",
                            "required": price_nrtc,
                            "received": amount_i64
                        }), 402
                        
                    # RUTHLESS CHECK 4: Is it valid?
                    if status == 'voided':
                        return jsonify({"error": "Transaction was voided"}), 402

                    # RUTHLESS CHECK 5: Replay Protection (Finding 6: Double-Spending TX ID)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS x402_spent_txs (
                            tx_hash TEXT PRIMARY KEY,
                            endpoint TEXT,
                            spent_at INTEGER
                        )
                    """)
                    
                    is_spent = conn.execute("SELECT 1 FROM x402_spent_txs WHERE tx_hash = ? AND endpoint = ?", 
                                           (tx_id, request.path)).fetchone()
                    if is_spent:
                        return jsonify({"error": "Transaction ID already used for this service"}), 402
                    
                    conn.execute("INSERT INTO x402_spent_txs (tx_hash, endpoint, spent_at) VALUES (?, ?, ?)",
                                 (tx_id, request.path, int(time.time())))
                    conn.commit()

            except Exception as e:
                log.error(f"Ruthless verification failed: {e}")
                return jsonify({"error": "Ledger verification failure"}), 500

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def register_agent_routes(app_or_bp, db_path):
    # Apply the same ruthless logic to the /reputation/vote endpoint
    @app_or_bp.route("/reputation/vote", methods=["POST"])
    def reputation_vote():
        data = request.get_json(silent=True) or {}
        voter_id = data.get("voter_id")
        target_entity = data.get("target_entity")
        donation_nrtc = data.get("donation_nrtc", 0)
        tx_id = data.get("tx_id")
        
        service_addr = os.environ.get("RC_SERVICE_ADDR")

        if not voter_id or not target_entity:
            return jsonify({"error": "Missing voter_id or target_entity"}), 400

        try:
            with sqlite3.connect(db_path) as conn:
                # Rate Limiting
                now = int(time.time())
                count = conn.execute("SELECT COUNT(*) FROM reputation_votes WHERE voter_id = ? AND created_at > ?", (voter_id, now - 3600)).fetchone()[0]
                if count >= 10: return jsonify({"error": "Rate limit exceeded"}), 429

                # Ruthless Donation Verification
                if donation_nrtc > 0:
                    if not tx_id: return jsonify({"error": "tx_id required for donations"}), 400
                    row = conn.execute("SELECT status, amount_i64, to_miner FROM pending_ledger WHERE tx_hash = ?", (tx_id,)).fetchone()
                    
                    if not row: return jsonify({"error": "TX not found"}), 402
                    if row[0] == 'voided': return jsonify({"error": "TX voided"}), 402
                    if row[1] < donation_nrtc: return jsonify({"error": "TX amount mismatch"}), 402
                    if service_addr and row[2] != service_addr: return jsonify({"error": "TX sent to wrong recipient"}), 402

                conn.execute("INSERT INTO reputation_votes (voter_id, target_entity, vote_type, donation_nrtc, tx_id, created_at) VALUES (?, ?, 'upvote', ?, ?, ?)",
                             (voter_id, target_entity, donation_nrtc, tx_id, now))
                conn.commit()
        except Exception as e:
            return jsonify({"error": f"DB Error: {e}"}), 500

        return jsonify({"ok": True})

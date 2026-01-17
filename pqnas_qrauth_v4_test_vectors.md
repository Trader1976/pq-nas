# PQ-NAS QR-Auth v4 Test Vectors (Encoding: base64url, no padding)
These vectors are **fully deterministic** and meant for unit tests across Dart / Python / C 
/ Rust. **Important:** The phone signature algorithm here is **Ed25519-TEST** so you can 
validate the entire pipeline immediately. In production, replace it with your DNA identity 
signature scheme (ML-DSA / Dilithium-class) while keeping the same canonicalization and 
message construction rules. ---
## Server key (Ed25519) — test only
- private key bytes: 0x1f repeated 32 times - public key (raw, base64url): ``` 
QwRr_kCSs-lJlOraFdzCDYqqB7ZY_TlU644O-4vcpd4 ```
## Phone key (Ed25519) — test only
- private key bytes: 0x2e repeated 32 times - public key (raw, base64url): ``` 
W4ZJwM_Nvnil_5Yu36SJFN_UWvIq_jWN4fTdfkVn1co ``` ---
## req_payload_canonical_json (JCS / sorted keys)
``` 
{"aud":"dna-messenger","chal":"ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8","exp":1768620060,"iat":1768620000,"iss":"pq-nas","nonce":"oaKjpKWmp6ipqqusra6vAA","origin":"https://nas.example.com","scope":"pqnas.login","sid":"Tr85XMc-udOkg4D-CTOKuw4-0brHQX_U","typ":"req","v":4} 
```
## req_payload_b64
``` 
eyJhdWQiOiJkbmEtbWVzc2VuZ2VyIiwiY2hhbCI6IkFCRWlNMFJWWm5lSW1hcTd6TjN1X3dBUklqTkVWV1ozaUptcXU4emQ3djgiLCJleHAiOjE3Njg2MjAwNjAsImlhdCI6MTc2ODYyMDAwMCwiaXNzIjoicHEtbmFzIiwibm9uY2UiOiJvYUtqcEtXbXA2aXBxcXVzcmE2dkFBIiwib3JpZ2luIjoiaHR0cHM6Ly9uYXMuZXhhbXBsZS5jb20iLCJzY29wZSI6InBxbmFzLmxvZ2luIiwic2lkIjoiVHI4NVhNYy11ZE9rZzRELUNUT0t1dzQtMGJySFFYX1UiLCJ0eXAiOiJyZXEiLCJ2Ijo0fQ 
```
## server_signature_b64 (Ed25519 over SHA256(req_payload_canonical_json_bytes))
``` fMjMoBwaWm07hTLEte1yrIoTUROX0hR7Sgn6V_TOrdlD8tOMXhQei3CwAqawm2oyeTLh_Mo7LVAzK4saHyOMCw 
```
## req_token
``` 
eyJhdWQiOiJkbmEtbWVzc2VuZ2VyIiwiY2hhbCI6IkFCRWlNMFJWWm5lSW1hcTd6TjN1X3dBUklqTkVWV1ozaUptcXU4emQ3djgiLCJleHAiOjE3Njg2MjAwNjAsImlhdCI6MTc2ODYyMDAwMCwiaXNzIjoicHEtbmFzIiwibm9uY2UiOiJvYUtqcEtXbXA2aXBxcXVzcmE2dkFBIiwib3JpZ2luIjoiaHR0cHM6Ly9uYXMuZXhhbXBsZS5jb20iLCJzY29wZSI6InBxbmFzLmxvZ2luIiwic2lkIjoiVHI4NVhNYy11ZE9rZzRELUNUT0t1dzQtMGJySFFYX1UiLCJ0eXAiOiJyZXEiLCJ2Ijo0fQ.fMjMoBwaWm07hTLEte1yrIoTUROX0hR7Sgn6V_TOrdlD8tOMXhQei3CwAqawm2oyeTLh_Mo7LVAzK4saHyOMCw 
``` ---
## req_hash_b64 (base64url(SHA256(UTF8(req_token))))
``` Lfy_E3Q7vSm7JWJvL46QJCDVqAy_-sKtZEjQ0Uq1KKw ```
## fingerprint_b64 (base64url(SHA3-512(phone_public_key_raw_bytes)))
``` b94o8mKkp0bTTGP2SBZNHTeawBIqZTg4CW5d6KXInBNNWOnH7Ztk_aArpduzt4OYP93loQvvLTBTf0vEjAXEIw 
```
## signing_message_utf8 (exact bytes, \n linefeeds, no trailing newline)
``` DNAQR-V4 Lfy_E3Q7vSm7JWJvL46QJCDVqAy_-sKtZEjQ0Uq1KKw 
b94o8mKkp0bTTGP2SBZNHTeawBIqZTg4CW5d6KXInBNNWOnH7Ztk_aArpduzt4OYP93loQvvLTBTf0vEjAXEIw 
1768620005 ```
## prehash_sha3_512_b64 (base64url(SHA3-512(signing_message_utf8_bytes)))
``` Ko5vuaCtRcKrV0EhxVqmO3EXfhgVNtF-PQdJ6PiQSGgEnQ2_VNFYmeyKGkC7Wi6YYzaW51M6xvnVTpWKqNvRKQ 
```
## phone_signature_b64 (Ed25519 over prehash bytes)
``` fZm-JV26puLLvWt_bm63RIwudrJBMTd0P_20g5uJbK69MrbSaSLuJ8RZi5h9m60uX-uC5VYGCoZYmHJGtYYfCw 
``` ---
## proof_payload_canonical_json (JCS / sorted keys)
``` 
{"device":{"app":"dna-messenger","platform":"android","ver":"0.99.105"},"fingerprint":"b94o8mKkp0bTTGP2SBZNHTeawBIqZTg4CW5d6KXInBNNWOnH7Ztk_aArpduzt4OYP93loQvvLTBTf0vEjAXEIw","pk":"W4ZJwM_Nvnil_5Yu36SJFN_UWvIq_jWN4fTdfkVn1co","pk_alg":"Ed25519-TEST","req":"eyJhdWQiOiJkbmEtbWVzc2VuZ2VyIiwiY2hhbCI6IkFCRWlNMFJWWm5lSW1hcTd6TjN1X3dBUklqTkVWV1ozaUptcXU4emQ3djgiLCJleHAiOjE3Njg2MjAwNjAsImlhdCI6MTc2ODYyMDAwMCwiaXNzIjoicHEtbmFzIiwibm9uY2UiOiJvYUtqcEtXbXA2aXBxcXVzcmE2dkFBIiwib3JpZ2luIjoiaHR0cHM6Ly9uYXMuZXhhbXBsZS5jb20iLCJzY29wZSI6InBxbmFzLmxvZ2luIiwic2lkIjoiVHI4NVhNYy11ZE9rZzRELUNUT0t1dzQtMGJySFFYX1UiLCJ0eXAiOiJyZXEiLCJ2Ijo0fQ.fMjMoBwaWm07hTLEte1yrIoTUROX0hR7Sgn6V_TOrdlD8tOMXhQei3CwAqawm2oyeTLh_Mo7LVAzK4saHyOMCw","ts":1768620005,"typ":"proof","v":4} 
```
## proof_payload_b64
``` 
eyJkZXZpY2UiOnsiYXBwIjoiZG5hLW1lc3NlbmdlciIsInBsYXRmb3JtIjoiYW5kcm9pZCIsInZlciI6IjAuOTkuMTA1In0sImZpbmdlcnByaW50IjoiYjk0bzhtS2twMGJUVEdQMlNCWk5IVGVhd0JJcVpUZzRDVzVkNktYSW5CTk5XT25IN1p0a19hQXJwZHV6dDRPWVA5M2xvUXZ2TFRCVGYwdkVqQVhFSXciLCJwayI6Ilc0Wkp3TV9Odm5pbF81WXUzNlNKRk5fVVd2SXFfaldONGZUZGZrVm4xY28iLCJwa19hbGciOiJFZDI1NTE5LVRFU1QiLCJyZXEiOiJleUpoZFdRaU9pSmtibUV0YldWemMyVnVaMlZ5SWl3aVkyaGhiQ0k2SWtGQ1JXbE5NRkpXV201bFNXMWhjVGQ2VGpOMVgzZEJVa2xxVGtWV1Yxb3phVXB0Y1hVNGVtUTNkamdpTENKbGVIQWlPakUzTmpnMk1qQXdOakFzSW1saGRDSTZNVGMyT0RZeU1EQXdNQ3dpYVhOeklqb2ljSEV0Ym1Geklpd2libTl1WTJVaU9pSnZZVXRxY0V0WGJYQTJhWEJ4Y1hWemNtRTJka0ZCSWl3aWIzSnBaMmx1SWpvaWFIUjBjSE02THk5dVlYTXVaWGhoYlhCc1pTNWpiMjBpTENKelkyOXdaU0k2SW5CeGJtRnpMbXh2WjJsdUlpd2ljMmxrSWpvaVZISTROVmhOWXkxMVpFOXJaelJFTFVOVVQwdDFkelF0TUdKeVNGRllYMVVpTENKMGVYQWlPaUp5WlhFaUxDSjJJam8wZlEuZk1qTW9Cd2FXbTA3aFRMRXRlMXlySW9UVVJPWDBoUjdTZ242Vl9UT3JkbEQ4dE9NWGhRZWkzQ3dBcWF3bTJveWVUTGhfTW83TFZBeks0c2FIeU9NQ3ciLCJ0cyI6MTc2ODYyMDAwNSwidHlwIjoicHJvb2YiLCJ2Ijo0fQ 
```
## proof_token
``` 
eyJkZXZpY2UiOnsiYXBwIjoiZG5hLW1lc3NlbmdlciIsInBsYXRmb3JtIjoiYW5kcm9pZCIsInZlciI6IjAuOTkuMTA1In0sImZpbmdlcnByaW50IjoiYjk0bzhtS2twMGJUVEdQMlNCWk5IVGVhd0JJcVpUZzRDVzVkNktYSW5CTk5XT25IN1p0a19hQXJwZHV6dDRPWVA5M2xvUXZ2TFRCVGYwdkVqQVhFSXciLCJwayI6Ilc0Wkp3TV9Odm5pbF81WXUzNlNKRk5fVVd2SXFfaldONGZUZGZrVm4xY28iLCJwa19hbGciOiJFZDI1NTE5LVRFU1QiLCJyZXEiOiJleUpoZFdRaU9pSmtibUV0YldWemMyVnVaMlZ5SWl3aVkyaGhiQ0k2SWtGQ1JXbE5NRkpXV201bFNXMWhjVGQ2VGpOMVgzZEJVa2xxVGtWV1Yxb3phVXB0Y1hVNGVtUTNkamdpTENKbGVIQWlPakUzTmpnMk1qQXdOakFzSW1saGRDSTZNVGMyT0RZeU1EQXdNQ3dpYVhOeklqb2ljSEV0Ym1Geklpd2libTl1WTJVaU9pSnZZVXRxY0V0WGJYQTJhWEJ4Y1hWemNtRTJka0ZCSWl3aWIzSnBaMmx1SWpvaWFIUjBjSE02THk5dVlYTXVaWGhoYlhCc1pTNWpiMjBpTENKelkyOXdaU0k2SW5CeGJtRnpMbXh2WjJsdUlpd2ljMmxrSWpvaVZISTROVmhOWXkxMVpFOXJaelJFTFVOVVQwdDFkelF0TUdKeVNGRllYMVVpTENKMGVYQWlPaUp5WlhFaUxDSjJJam8wZlEuZk1qTW9Cd2FXbTA3aFRMRXRlMXlySW9UVVJPWDBoUjdTZ242Vl9UT3JkbEQ4dE9NWGhRZWkzQ3dBcWF3bTJveWVUTGhfTW83TFZBeks0c2FIeU9NQ3ciLCJ0cyI6MTc2ODYyMDAwNSwidHlwIjoicHJvb2YiLCJ2Ijo0fQ.fZm-JV26puLLvWt_bm63RIwudrJBMTd0P_20g5uJbK69MrbSaSLuJ8RZi5h9m60uX-uC5VYGCoZYmHJGtYYfCw 
``` ---
## Expected verification result
- req_token: ✅ valid (signature matches, exp/iat ok) - fingerprint binding: ✅ valid 
(fingerprint matches SHA3-512(pk))
- proof_token: ✅ valid (signature matches signing_message prehash)

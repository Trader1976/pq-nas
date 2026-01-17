import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

String b64urlNoPadEncode(Uint8List bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}

Uint8List b64urlNoPadDecode(String s) {
  // Dart base64Url requires padding; add it back.
  final padLen = (4 - (s.length % 4)) % 4;
  final padded = s + ('=' * padLen);
  return Uint8List.fromList(base64Url.decode(padded));
}

Uint8List sha256(Uint8List data) {
  final d = SHA256Digest();
  return d.process(data);
}

Uint8List sha3_512(Uint8List data) {
  final d = SHA3Digest(512);
  return d.process(data);
}

/// Extract ``` fenced block after "## <header>"
String extractFenced(String md, String header) {
  final re = RegExp('## ${RegExp.escape(header)}\\s+```([\\s\\S]*?)```');
  final m = re.firstMatch(md);
  if (m == null) throw StateError('Missing fenced block: $header');
  return m.group(1)!.trim();
}

/// Extract server public key base64url from the valid vectors file
String extractServerPk(String md) {
  final re = RegExp(r'Server key .*?public key \(raw, base64url\):\s*```([\s\S]*?)```');
  final m = re.firstMatch(md);
  if (m == null) throw StateError('Missing server public key block');
  return m.group(1)!.trim();
}

void ed25519Verify(Uint8List publicKeyRaw, Uint8List msg, Uint8List sig) {
  final verifier = Signer('Ed25519');
  final pub = PublicKeyParameter(Ed25519PublicKey(publicKeyRaw));
  verifier.init(false, pub);
  final ok = verifier.verifySignature(msg, Ed25519Signature(sig));
  if (!ok) throw StateError('Ed25519 signature verify failed');
}

Map<String, dynamic> verifyReqToken(String reqToken, String serverPkB64) {
  final parts = reqToken.split('.');
  if (parts.length != 2) throw StateError('req_token must be payload.sig');
  final payloadBytes = b64urlNoPadDecode(parts[0]);
  final sigBytes = b64urlNoPadDecode(parts[1]);

  final payload = json.decode(utf8.decode(payloadBytes)) as Map<String, dynamic>;

  // Server signs SHA256(payloadBytes)
  final digest = sha256(payloadBytes);
  final serverPkRaw = b64urlNoPadDecode(serverPkB64);
  ed25519Verify(serverPkRaw, digest, sigBytes);

  if (payload['v'] != 4 || payload['typ'] != 'req') {
    throw StateError('req typ/v mismatch');
  }
  return payload;
}

Map<String, dynamic> verifyProofToken(String proofToken, String serverPkB64) {
  final parts = proofToken.split('.');
  if (parts.length != 2) throw StateError('proof_token must be payload.sig');

  final proofPayloadBytes = b64urlNoPadDecode(parts[0]);
  final phoneSigBytes = b64urlNoPadDecode(parts[1]);
  final proof = json.decode(utf8.decode(proofPayloadBytes)) as Map<String, dynamic>;

  if (proof['v'] != 4 || proof['typ'] != 'proof') {
    throw StateError('proof typ/v mismatch');
  }

  final reqToken = proof['req'] as String;
  final fingerprintB64 = proof['fingerprint'] as String;
  final pkB64 = proof['pk'] as String;
  final ts = (proof['ts'] as num).toInt();

  // Verify server-signed req token
  verifyReqToken(reqToken, serverPkB64);

  // Fingerprint binding
  final pkRaw = b64urlNoPadDecode(pkB64);
  final fpCalc = b64urlNoPadEncode(sha3_512(pkRaw));
  if (fpCalc != fingerprintB64) {
    throw StateError('fingerprint binding mismatch');
  }

  // req_hash_b64 = b64url(SHA256(UTF8(req_token)))
  final reqHashB64 = b64urlNoPadEncode(sha256(Uint8List.fromList(utf8.encode(reqToken))));

  // Signing message (exact newlines, no trailing newline)
  final msg = 'DNAQR-V4\n$reqHashB64\n$fingerprintB64\n$ts';
  final prehash = sha3_512(Uint8List.fromList(utf8.encode(msg)));

  // Phone Ed25519 verifies over prehash bytes
  ed25519Verify(pkRaw, prehash, phoneSigBytes);

  return proof;
}

void main(List<String> args) {
  final validPath = File('pqnas_qrauth_v4_test_vectors.md');
  final invalidPath = File('pqnas_qrauth_v4_test_vector_invalid.md');

  if (!validPath.existsSync()) {
    stderr.writeln('Missing ${validPath.path}. Put vectors in repo root or adjust paths.');
    exit(2);
  }

  final validMd = validPath.readAsStringSync();
  final serverPkB64 = extractServerPk(validMd);
  final proofToken = extractFenced(validMd, 'proof_token');

  try {
    verifyProofToken(proofToken, serverPkB64);
    stdout.writeln('VALID: PASS');
  } catch (e) {
    stdout.writeln('VALID: FAIL ($e)');
    exit(1);
  }

  if (invalidPath.existsSync()) {
    final invalidMd = invalidPath.readAsStringSync();
    final tamperedReq = RegExp(r'## Tampered req_token .*?```([\s\S]*?)```')
        .firstMatch(invalidMd)!.group(1)!.trim();
    final wrongReqHashB64 = RegExp(r'## Wrong req_hash_b64\s+```([\s\S]*?)```')
        .firstMatch(invalidMd)!.group(1)!.trim();

    final calcWrong = b64urlNoPadEncode(
      sha256(Uint8List.fromList(utf8.encode(tamperedReq))),
    );

    if (calcWrong != wrongReqHashB64) {
      stdout.writeln('INVALID: FAIL (invalid vector file mismatch)');
      exit(1);
    }

    final correctReq = extractFenced(validMd, 'req_token');
    final correctHash = b64urlNoPadEncode(
      sha256(Uint8List.fromList(utf8.encode(correctReq))),
    );

    if (correctHash == wrongReqHashB64) {
      stdout.writeln('INVALID: FAIL (wrong hash equals correct hash)');
      exit(1);
    }

    stdout.writeln('INVALID: PASS (expected mismatch detected)');
  } else {
    stdout.writeln('INVALID: SKIP (file missing)');
  }
}

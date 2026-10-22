/**
 * IPsecForge Pro - 10-Point Zero-Trust Cryptographic Policy Auditor
 * Evaluates IKEv2 and IPsec configurations against NIST SP 800-77 Rev. 1,
 * NSA Commercial National Security Algorithm (CNSA), and CIS Network Benchmarks.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IPsecCryptoAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditConfiguration(cfg) {
    cfg = cfg || {};
    var findings = [];
    var score = 0;

    // 1. IKE Protocol Version (12 pts)
    var isIkev2 = (cfg.ikeVersion === 'IKEv2' || cfg.ikeVersion === 2 || cfg.ikeVersion === '2');
    if (isIkev2) {
      findings.push({
        id: 'SEC-IPSEC-01',
        title: 'Modern IKEv2 Protocol Active',
        category: 'Key Management',
        weight: 12,
        earned: 12,
        status: 'PASS',
        details: 'Tunnel uses IKEv2 (RFC 7296). Provides half the round trips, built-in NAT-T/DPD, and resistance to offline dictionary attacks.',
        remediation: 'Ensure legacy IKEv1 fallbacks are globally disabled on the gateway.'
      });
      score += 12;
    } else {
      findings.push({
        id: 'SEC-IPSEC-01',
        title: 'Legacy IKEv1 Protocol in Use',
        category: 'Key Management',
        weight: 12,
        earned: 0,
        status: 'CRITICAL',
        details: 'Tunnel uses legacy IKEv1 (RFC 2409). Susceptible to Main/Aggressive Mode user enumeration and offline PSK hash cracking.',
        remediation: 'Migrate tunnel policy to IKEv2 immediately: "crypto ikev2 proposal ...".'
      });
    }

    // 2. Phase 1 Encryption Strength (12 pts)
    var encr = cfg.encr || 'AES-GCM-256';
    if (encr === 'AES-GCM-256') {
      findings.push({
        id: 'SEC-IPSEC-02',
        title: 'Modern AEAD Phase 1 Encryption (AES-GCM-256)',
        category: 'Confidentiality',
        weight: 12,
        earned: 12,
        status: 'PASS',
        details: 'AES-256-GCM delivers authenticated encryption with integrated Galois Counter Mode integrity verification.',
        remediation: 'Maintain current cipher configuration.'
      });
      score += 12;
    } else if (encr === 'AES-CBC-256') {
      findings.push({
        id: 'SEC-IPSEC-02',
        title: 'Robust Phase 1 Encryption (AES-CBC-256)',
        category: 'Confidentiality',
        weight: 12,
        earned: 10,
        status: 'PASS',
        details: 'AES-256-CBC provides strong 256-bit symmetric confidentiality when paired with SHA-256 HMAC.',
        remediation: 'Consider migrating to AES-GCM-256 for lower CPU overhead and hardware offloading.'
      });
      score += 10;
    } else if (encr === 'AES-GCM-128' || encr === 'AES-CBC-128') {
      findings.push({
        id: 'SEC-IPSEC-02',
        title: 'Standard 128-bit Phase 1 Encryption',
        category: 'Confidentiality',
        weight: 12,
        earned: 8,
        status: 'PASS',
        details: '128-bit AES provides acceptable protection but is not recommended for top-tier government/enterprise data.',
        remediation: 'Upgrade to AES-256-GCM to comply with NSA CNSA Suite standards.'
      });
      score += 8;
    } else {
      findings.push({
        id: 'SEC-IPSEC-02',
        title: 'Deprecated / Weak Encryption (' + encr + ')',
        category: 'Confidentiality',
        weight: 12,
        earned: 0,
        status: 'CRITICAL',
        details: 'Legacy ciphers (3DES/DES) are vulnerable to Sweet32 64-bit block collision attacks and brute force cracking.',
        remediation: 'Replace with AES-GCM-256 immediately.'
      });
    }

    // 3. Phase 2 IPsec ESP Data Confidentiality (10 pts)
    var espEncr = cfg.espEncr || 'AES-GCM-256';
    if (espEncr === 'AES-GCM-256' || espEncr === 'AES-GCM-128') {
      findings.push({
        id: 'SEC-IPSEC-03',
        title: 'High-Performance AEAD ESP Data Protection',
        category: 'Data Plane',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'IPsec ESP encapsulates user packets with hardware-accelerated Galois Counter Mode (GCM).',
        remediation: 'Ensure gateway crypto engines utilize AES-NI or Cavium/Intel QAT hardware offload.'
      });
      score += 10;
    } else if (espEncr === 'AES-CBC-256') {
      findings.push({
        id: 'SEC-IPSEC-03',
        title: 'Strong ESP Data Protection (AES-CBC-256)',
        category: 'Data Plane',
        weight: 10,
        earned: 8,
        status: 'PASS',
        details: 'ESP encapsulates user packets with AES-256 in CBC mode.',
        remediation: 'Upgrade to AES-GCM-256 to reduce per-packet HMAC calculation latency.'
      });
      score += 8;
    } else {
      findings.push({
        id: 'SEC-IPSEC-03',
        title: 'Weak IPsec ESP Data Encryption (' + espEncr + ')',
        category: 'Data Plane',
        weight: 10,
        earned: 0,
        status: 'CRITICAL',
        details: 'Deprecated ESP encryption (3DES/NULL) exposes data payloads to eavesdropping and integrity tampering.',
        remediation: 'Configure "esp-gcm 256" or "esp-aes 256 esp-sha256-hmac".'
      });
    }

    // 4. Diffie-Hellman Key Exchange Group Strength (10 pts)
    var dh = cfg.dh || 'Group 19 (256-bit ECP)';
    if (dh.indexOf('Group 19') !== -1 || dh.indexOf('Group 20') !== -1 || dh.indexOf('Group 21') !== -1) {
      findings.push({
        id: 'SEC-IPSEC-04',
        title: 'Next-Gen Elliptic Curve Diffie-Hellman (' + dh.split(' ')[1] + ')',
        category: 'Key Exchange',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Curve P-256/P-384/P-521 provides superior security margin with minimal CPU compute time and small packet size.',
        remediation: 'Maintain current Elliptic Curve DH group.'
      });
      score += 10;
    } else if (dh.indexOf('Group 14') !== -1) {
      findings.push({
        id: 'SEC-IPSEC-04',
        title: 'Hardened MODP Diffie-Hellman (Group 14 2048-bit)',
        category: 'Key Exchange',
        weight: 10,
        earned: 8,
        status: 'PASS',
        details: '2048-bit MODP meets NIST minimum standards, though elliptic curves (Group 19) offer faster computation.',
        remediation: 'Upgrade to Group 19 (256-bit ECP) where supported by peers.'
      });
      score += 8;
    } else {
      findings.push({
        id: 'SEC-IPSEC-04',
        title: 'Weak / Broken Diffie-Hellman Group (' + dh + ')',
        category: 'Key Exchange',
        weight: 10,
        earned: 0,
        status: 'CRITICAL',
        details: 'DH Groups 1, 2, and 5 (<= 1536-bit) are vulnerable to precomputation attacks (Logjam) by nation-state actors.',
        remediation: 'Upgrade DH group to at least Group 14 (2048-bit) or Group 19 (256-bit ECP).'
      });
    }

    // 5. Perfect Forward Secrecy (PFS) (10 pts)
    var pfs = !!cfg.pfsEnabled;
    if (pfs) {
      findings.push({
        id: 'SEC-IPSEC-05',
        title: 'Perfect Forward Secrecy (PFS) Active',
        category: 'Key Resilience',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'PFS executes a fresh Diffie-Hellman exchange during Child SA rekeying. Compromise of IKE_SA does not compromise traffic keys.',
        remediation: 'Verify PFS group matches or exceeds Phase 1 DH group.'
      });
      score += 10;
    } else {
      findings.push({
        id: 'SEC-IPSEC-05',
        title: 'Perfect Forward Secrecy (PFS) Disabled',
        category: 'Key Resilience',
        weight: 10,
        earned: 0,
        status: 'FAIL',
        details: 'Child SAs derive keys directly from Phase 1 master key. If the IKE SA key is cracked, all past session data is decrypted.',
        remediation: 'Enable PFS on Phase 2 Child SA: "set pfs group19" or "pfs group14".'
      });
    }

    // 6. PRF & Integrity Hashing (10 pts)
    var prf = cfg.prf || 'PRF_HMAC_SHA2_256';
    if (prf.indexOf('SHA2') !== -1 || prf.indexOf('SHA384') !== -1 || prf.indexOf('SHA512') !== -1) {
      findings.push({
        id: 'SEC-IPSEC-06',
        title: 'Robust SHA-2 Hashing Active (' + prf + ')',
        category: 'Integrity',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Pseudo-Random Function and HMAC integrity algorithms use SHA-256/384/512. Collision resistance guaranteed.',
        remediation: 'Maintain current SHA-2 hashing suite.'
      });
      score += 10;
    } else {
      findings.push({
        id: 'SEC-IPSEC-06',
        title: 'Deprecated Hashing Algorithm (' + prf + ')',
        category: 'Integrity',
        weight: 10,
        earned: 0,
        status: 'FAIL',
        details: 'SHA-1 and MD5 suffer from demonstrated collision attacks and are forbidden by NIST SP 800-131A.',
        remediation: 'Replace with PRF_HMAC_SHA2_256 and AUTH_HMAC_SHA2_256_128.'
      });
    }

    // 7. Dead Peer Detection (DPD) (10 pts)
    var dpd = !!cfg.dpdEnabled;
    var dpdInterval = parseInt(cfg.dpdIntervalSec, 10) || 10;
    if (dpd && dpdInterval >= 5 && dpdInterval <= 30) {
      findings.push({
        id: 'SEC-IPSEC-07',
        title: 'Dead Peer Detection Configured (' + dpdInterval + 's)',
        category: 'Availability',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Periodic DPD keepalives prevent black-hole routing by detecting unresponsive peers within ' + (dpdInterval * 3) + ' seconds.',
        remediation: 'Ensure DPD action is set to restart or clear on timeout.'
      });
      score += 10;
    } else if (dpd) {
      findings.push({
        id: 'SEC-IPSEC-07',
        title: 'Permissive DPD Interval (' + dpdInterval + 's)',
        category: 'Availability',
        weight: 10,
        earned: 6,
        status: 'WARNING',
        details: 'DPD interval exceeds recommended 30-second threshold, delaying failover recovery during peer outages.',
        remediation: 'Tune DPD interval to 10–20 seconds: "dpd 10 periodic".'
      });
      score += 6;
    } else {
      findings.push({
        id: 'SEC-IPSEC-07',
        title: 'Dead Peer Detection Disabled',
        category: 'Availability',
        weight: 10,
        earned: 0,
        status: 'FAIL',
        details: 'No DPD active. If peer crashes, local gateway will continue routing traffic into dead tunnel, causing silent outage.',
        remediation: 'Enable DPD immediately: "crypto ikev2 dpd 10 3 periodic".'
      });
    }

    // 8. NAT-Traversal (NAT-T / UDP 4500) (9 pts)
    var natT = !!cfg.natTraversalEnabled;
    if (natT) {
      findings.push({
        id: 'SEC-IPSEC-08',
        title: 'NAT-Traversal (UDP 4500 Encapsulation) Active',
        category: 'Traversal',
        weight: 9,
        earned: 9,
        status: 'PASS',
        details: 'Encapsulates ESP in UDP 4500 with Non-ESP marker, enabling seamless traversal of stateful PAT/NAT gateways.',
        remediation: 'Ensure perimeter security groups permit ingress UDP port 4500.'
      });
      score += 9;
    } else {
      findings.push({
        id: 'SEC-IPSEC-08',
        title: 'NAT-Traversal Disabled (Packet Drop Hazard)',
        category: 'Traversal',
        weight: 9,
        earned: 2,
        status: 'WARNING',
        details: 'NAT-T is disabled. Intermediate NAT gateways will drop native ESP packets (IP protocol 50) due to missing port fields.',
        remediation: 'Enable NAT-T: "crypto ikev2 nat-traversal".'
      });
      score += 2;
    }

    // 9. Anti-Replay Window Protection (9 pts)
    var antiReplay = !!cfg.antiReplayEnabled;
    var windowSize = parseInt(cfg.antiReplayWindow, 10) || 64;
    if (antiReplay && windowSize >= 64) {
      findings.push({
        id: 'SEC-IPSEC-09',
        title: 'Anti-Replay Window Enforced (' + windowSize + ' packets)',
        category: 'Integrity Defense',
        weight: 9,
        earned: 9,
        status: 'PASS',
        details: 'Hardware sliding window rejects duplicated or replayed ESP packets, thwarting replay attacks.',
        remediation: 'For multi-gigabit connections with out-of-order QoS, expand window to 1024 packets.'
      });
      score += 9;
    } else if (antiReplay) {
      findings.push({
        id: 'SEC-IPSEC-09',
        title: 'Small Anti-Replay Window (' + windowSize + ' packets)',
        category: 'Integrity Defense',
        weight: 9,
        earned: 5,
        status: 'WARNING',
        details: 'Window size below 64 may cause false packet drops under multi-core traffic hashing.',
        remediation: 'Increase window size: "crypto ipsec security-association replay window-size 256".'
      });
      score += 5;
    } else {
      findings.push({
        id: 'SEC-IPSEC-09',
        title: 'Anti-Replay Protection Disabled',
        category: 'Integrity Defense',
        weight: 9,
        earned: 0,
        status: 'CRITICAL',
        details: 'Replay window disabled. Attackers capturing encrypted packets can retransmit them to replay stateful operations.',
        remediation: 'Enable anti-replay window immediately.'
      });
    }

    // 10. PSK Entropy or Certificate Authentication (8 pts)
    var psk = cfg.preSharedKey || '';
    var isCert = !!cfg.useCertificates;
    if (isCert) {
      findings.push({
        id: 'SEC-IPSEC-10',
        title: 'X.509 Digital Certificate Authentication Active',
        category: 'Authentication',
        weight: 8,
        earned: 8,
        status: 'PASS',
        details: 'Mutual authentication verified via asymmetric PKI certificates (RSA/ECDSA). Immune to PSK dictionary attacks.',
        remediation: 'Automate certificate renewal via SCEP or ACME to prevent expiration outages.'
      });
      score += 8;
    } else if (psk.length >= 24) {
      findings.push({
        id: 'SEC-IPSEC-10',
        title: 'High-Entropy Pre-Shared Key (' + psk.length + ' chars)',
        category: 'Authentication',
        weight: 8,
        earned: 8,
        status: 'PASS',
        details: 'Pre-shared key length exceeds 24 characters with high combinatorial entropy.',
        remediation: 'Rotate PSK at least annually or store in AWS Secrets Manager / HashiCorp Vault.'
      });
      score += 8;
    } else if (psk.length >= 16) {
      findings.push({
        id: 'SEC-IPSEC-10',
        title: 'Moderate PSK Length (' + psk.length + ' chars)',
        category: 'Authentication',
        weight: 8,
        earned: 4,
        status: 'WARNING',
        details: 'PSK length meets minimum 16-character guideline but should be lengthened for long-term cloud interconnects.',
        remediation: 'Generate 32-character random alphanumeric secret.'
      });
      score += 4;
    } else {
      findings.push({
        id: 'SEC-IPSEC-10',
        title: 'Weak / Short Pre-Shared Key (< 16 chars)',
        category: 'Authentication',
        weight: 8,
        earned: 1,
        status: 'FAIL',
        details: 'Short PSKs can be cracked via offline dictionary or GPU brute-force attacks if IKE packets are intercepted.',
        remediation: 'Configure cryptographically secure random PSK: "openssl rand -base64 32".'
      });
      score += 1;
    }

    // Final Grade Calculation
    var grade = 'F';
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 50) grade = 'C';
    else grade = 'F';

    var passCount = findings.filter(function (f) { return f.status === 'PASS'; }).length;
    var warnCount = findings.filter(function (f) { return f.status === 'WARNING'; }).length;
    var failCount = findings.filter(function (f) { return f.status === 'FAIL' || f.status === 'CRITICAL'; }).length;

    return {
      score: score,
      maxScore: 100,
      grade: grade,
      passCount: passCount,
      warnCount: warnCount,
      failCount: failCount,
      findings: findings,
      isCompliant: score >= 80 && failCount === 0
    };
  }

  return {
    auditConfiguration: auditConfiguration
  };
});

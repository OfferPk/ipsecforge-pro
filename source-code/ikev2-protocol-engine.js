/**
 * IPsecForge Pro - IETF RFC 7296 (IKEv2) & RFC 4303 (IPsec ESP) Protocol Engine
 * Encodes, dissects, and simulates IKEv2 packet exchanges, proposals, and transform payloads.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IKEv2ProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // IKEv2 Payload Types (RFC 7296 Section 3.2)
  var PAYLOAD_TYPES = {
    NO_NEXT: 0,
    SA: 33,       // Security Association
    KE: 34,       // Key Exchange
    IDI: 35,      // Identification - Initiator
    IDR: 36,      // Identification - Responder
    CERT: 37,     // Certificate
    CERTREQ: 38,  // Certificate Request
    AUTH: 39,     // Authentication
    NONCE: 40,    // Nonce (Ni / Nr)
    NOTIFY: 41,   // Notify
    DELETE: 42,   // Delete
    VENDOR: 43,   // Vendor ID
    TSI: 44,      // Traffic Selector - Initiator
    TSR: 45,      // Traffic Selector - Responder
    SK: 46        // Encrypted and Authenticated
  };

  // Exchange Types (RFC 7296 Section 3.1)
  var EXCHANGE_TYPES = {
    IKE_SA_INIT: 34,
    IKE_AUTH: 35,
    CREATE_CHILD_SA: 36,
    INFORMATIONAL: 37
  };

  // Transform Types (RFC 7296 Section 3.3.2)
  var TRANSFORM_TYPES = {
    ENCR: 1,  // Encryption Algorithm
    PRF: 2,   // Pseudo-random Function
    INTEG: 3, // Integrity Algorithm
    DH: 4,    // Diffie-Hellman Group
    ESN: 5    // Extended Sequence Numbers
  };

  // Transform IDs
  var ENCR_IDS = {
    'AES-GCM-256': { id: 20, keyLen: 256, isAead: true },
    'AES-GCM-128': { id: 20, keyLen: 128, isAead: true },
    'AES-CBC-256': { id: 12, keyLen: 256, isAead: false },
    'AES-CBC-128': { id: 12, keyLen: 128, isAead: false },
    '3DES-CBC':    { id: 3,  keyLen: 192, isAead: false }
  };

  var PRF_IDS = {
    'PRF_HMAC_SHA2_256': 5,
    'PRF_HMAC_SHA2_384': 6,
    'PRF_HMAC_SHA2_512': 7,
    'PRF_HMAC_SHA1':     2
  };

  var INTEG_IDS = {
    'NONE': 0,
    'AUTH_HMAC_SHA2_256_128': 12,
    'AUTH_HMAC_SHA2_384_192': 13,
    'AUTH_HMAC_SHA2_512_256': 14,
    'AUTH_HMAC_SHA1_96':      2
  };

  var DH_IDS = {
    'Group 14 (2048-bit MODP)': 14,
    'Group 19 (256-bit ECP)':   19,
    'Group 20 (384-bit ECP)':   20,
    'Group 21 (521-bit ECP)':   21,
    'Group 2 (1024-bit MODP)':   2
  };

  function parseHexSPI(hexStr, defaultHex) {
    var cleaned = (hexStr || defaultHex || '0000000000000000').replace(/[^0-9a-fA-F]/g, '');
    while (cleaned.length < 16) cleaned += '0';
    cleaned = cleaned.substring(0, 16);
    var bytes = [];
    for (var i = 0; i < 16; i += 2) {
      bytes.push(parseInt(cleaned.substr(i, 2), 16));
    }
    return bytes;
  }

  function encodeTransform(isLast, type, id, keyLen) {
    var out = [];
    out.push(isLast ? 0 : 3); // 0 = last, 3 = more transforms
    out.push(0);              // reserved
    var len = 8 + (keyLen ? 4 : 0);
    out.push((len >> 8) & 0xff);
    out.push(len & 0xff);
    out.push(type);
    out.push(0);              // reserved
    out.push((id >> 8) & 0xff);
    out.push(id & 0xff);

    if (keyLen) {
      // Attribute: Key Length (AF=1, Type=14, Value=keyLen)
      out.push(0x80);
      out.push(14);
      out.push((keyLen >> 8) & 0xff);
      out.push(keyLen & 0xff);
    }
    return out;
  }

  function encodeProposal(proposalNum, encrName, prfName, integName, dhName) {
    var encr = ENCR_IDS[encrName] || ENCR_IDS['AES-GCM-256'];
    var prfId = PRF_IDS[prfName] || 5;
    var integId = encr.isAead ? 0 : (INTEG_IDS[integName] || 12);
    var dhId = DH_IDS[dhName] || 19;

    var transformList = [];
    transformList.push({ type: TRANSFORM_TYPES.ENCR, id: encr.id, keyLen: encr.keyLen });
    transformList.push({ type: TRANSFORM_TYPES.PRF, id: prfId });
    if (!encr.isAead) {
      transformList.push({ type: TRANSFORM_TYPES.INTEG, id: integId });
    }
    transformList.push({ type: TRANSFORM_TYPES.DH, id: dhId });

    var transformsBytes = [];
    for (var i = 0; i < transformList.length; i++) {
      var isLast = (i === transformList.length - 1);
      var t = transformList[i];
      var tBytes = encodeTransform(isLast, t.type, t.id, t.keyLen);
      transformsBytes = transformsBytes.concat(tBytes);
    }

    var proposalBytes = [];
    proposalBytes.push(0);           // 0 = last proposal
    proposalBytes.push(0);           // reserved
    var propLen = 8 + transformsBytes.length;
    proposalBytes.push((propLen >> 8) & 0xff);
    proposalBytes.push(propLen & 0xff);
    proposalBytes.push(proposalNum); // proposal number
    proposalBytes.push(1);           // protocol ID: 1 = IKE
    proposalBytes.push(0);           // SPI size = 0 for IKE_SA_INIT
    proposalBytes.push(transformList.length); // number of transforms

    return proposalBytes.concat(transformsBytes);
  }

  function encodeSAPayload(nextPayload, encrName, prfName, integName, dhName) {
    var propBytes = encodeProposal(1, encrName, prfName, integName, dhName);
    var payloadLen = 4 + propBytes.length;
    var saBytes = [
      nextPayload,
      0, // critical = 0, reserved
      (payloadLen >> 8) & 0xff,
      payloadLen & 0xff
    ];
    return saBytes.concat(propBytes);
  }

  function encodeKEPayload(nextPayload, dhName) {
    var dhId = DH_IDS[dhName] || 19;
    var keyDataLen = (dhId === 19) ? 64 : ((dhId === 14) ? 256 : 96);
    var dummyKey = [];
    for (var i = 0; i < keyDataLen; i++) {
      dummyKey.push((i * 17 + 0x42) & 0xff);
    }

    var payloadLen = 8 + dummyKey.length;
    var keBytes = [
      nextPayload,
      0,
      (payloadLen >> 8) & 0xff,
      payloadLen & 0xff,
      (dhId >> 8) & 0xff,
      dhId & 0xff,
      0, 0 // reserved
    ];
    return keBytes.concat(dummyKey);
  }

  function encodeNoncePayload(nextPayload) {
    var nonceLen = 32; // 256-bit nonce
    var nonceBytes = [];
    for (var i = 0; i < nonceLen; i++) {
      nonceBytes.push((i * 31 + 0xa5) & 0xff);
    }
    var payloadLen = 4 + nonceLen;
    var nBytes = [
      nextPayload,
      0,
      (payloadLen >> 8) & 0xff,
      payloadLen & 0xff
    ];
    return nBytes.concat(nonceBytes);
  }

  function forgePacket(opts) {
    opts = opts || {};
    var spiInitiator = parseHexSPI(opts.spiInitiator, '4a82c9103e5b7f02');
    var spiResponder = parseHexSPI(opts.spiResponder, '0000000000000000');
    var exchangeType = opts.exchangeType || EXCHANGE_TYPES.IKE_SA_INIT;
    var messageId = opts.messageId !== undefined ? opts.messageId : 0;
    var isResponse = !!opts.isResponse;

    var encr = opts.encr || 'AES-GCM-256';
    var prf = opts.prf || 'PRF_HMAC_SHA2_256';
    var integ = opts.integ || 'NONE';
    var dh = opts.dh || 'Group 19 (256-bit ECP)';

    // Build payload chain: SA -> KE -> Nonce -> NO_NEXT
    var nonceBytes = encodeNoncePayload(PAYLOAD_TYPES.NO_NEXT);
    var keBytes = encodeKEPayload(PAYLOAD_TYPES.NONCE, dh);
    var saBytes = encodeSAPayload(PAYLOAD_TYPES.KE, encr, prf, integ, dh);

    var allPayloads = saBytes.concat(keBytes).concat(nonceBytes);
    var totalLen = 28 + allPayloads.length;

    var flags = 0;
    if (!isResponse) flags |= 0x08; // Initiator bit
    // Version 2.0 = 0x20
    var version = 0x20;

    var ikeHeader = [];
    // Initiator SPI (8 bytes)
    ikeHeader = ikeHeader.concat(spiInitiator);
    // Responder SPI (8 bytes)
    ikeHeader = ikeHeader.concat(spiResponder);
    // Next Payload: SA
    ikeHeader.push(PAYLOAD_TYPES.SA);
    // Version
    ikeHeader.push(version);
    // Exchange Type
    ikeHeader.push(exchangeType);
    // Flags
    ikeHeader.push(flags);
    // Message ID (4 bytes)
    ikeHeader.push((messageId >> 24) & 0xff);
    ikeHeader.push((messageId >> 16) & 0xff);
    ikeHeader.push((messageId >> 8) & 0xff);
    ikeHeader.push(messageId & 0xff);
    // Total Length (4 bytes)
    ikeHeader.push((totalLen >> 24) & 0xff);
    ikeHeader.push((totalLen >> 16) & 0xff);
    ikeHeader.push((totalLen >> 8) & 0xff);
    ikeHeader.push(totalLen & 0xff);

    var rawBytes = ikeHeader.concat(allPayloads);

    var exchangeName = 'IKE_SA_INIT';
    if (exchangeType === EXCHANGE_TYPES.IKE_AUTH) exchangeName = 'IKE_AUTH';
    else if (exchangeType === EXCHANGE_TYPES.CREATE_CHILD_SA) exchangeName = 'CREATE_CHILD_SA';
    else if (exchangeType === EXCHANGE_TYPES.INFORMATIONAL) exchangeName = 'INFORMATIONAL';

    return {
      rawBytes: rawBytes,
      totalLength: rawBytes.length,
      exchangeType: exchangeType,
      exchangeName: exchangeName,
      initiatorSpiHex: spiInitiator.map(function(b){ return ('0' + b.toString(16)).slice(-2); }).join(''),
      responderSpiHex: spiResponder.map(function(b){ return ('0' + b.toString(16)).slice(-2); }).join(''),
      messageId: messageId,
      encr: encr,
      prf: prf,
      integ: integ,
      dh: dh,
      payloadCount: 3
    };
  }

  function formatHexDump(bytes) {
    var lines = [];
    for (var i = 0; i < bytes.length; i += 16) {
      var chunk = bytes.slice(i, i + 16);
      var hex = [];
      var ascii = [];

      for (var j = 0; j < chunk.length; j++) {
        var b = chunk[j];
        hex.push(('0' + b.toString(16)).slice(-2));
        ascii.push((b >= 32 && b <= 126) ? String.fromCharCode(b) : '.');
      }

      while (hex.length < 16) {
        hex.push('  ');
        ascii.push(' ');
      }

      var hex1 = hex.slice(0, 8).join(' ');
      var hex2 = hex.slice(8).join(' ');
      var offset = ('0000' + i.toString(16)).slice(-4);
      lines.push(offset + '   ' + hex1 + '  ' + hex2 + '   |' + ascii.join('') + '|');
    }
    return lines.join('\n');
  }

  function simulateNegotiation(init, resp) {
    init = init || {};
    resp = resp || {};

    // 1. Check Encryption Algorithm
    if (init.encr !== resp.encr) {
      return {
        verdict: 'NO_PROPOSAL_CHOSEN',
        status: 'FAIL',
        errorStep: 'ENCR_MISMATCH',
        description: 'Initiator proposed ' + init.encr + ' but Responder configured with ' + resp.encr + '.',
        remediation: 'Align IKEv2 Phase 1 encryption algorithms (e.g., both use AES-GCM-256 or AES-CBC-256).'
      };
    }

    // 2. Check PRF Algorithm
    if (init.prf !== resp.prf) {
      return {
        verdict: 'NO_PROPOSAL_CHOSEN',
        status: 'FAIL',
        errorStep: 'PRF_MISMATCH',
        description: 'Initiator proposed PRF ' + init.prf + ' but Responder configured with ' + resp.prf + '.',
        remediation: 'Ensure both peers negotiate identical pseudo-random functions (e.g., PRF_HMAC_SHA2_256).'
      };
    }

    // 3. Check Integrity Algorithm (for non-AEAD ciphers)
    var encrMeta = ENCR_IDS[init.encr] || {};
    if (!encrMeta.isAead) {
      if (init.integ !== resp.integ) {
        return {
          verdict: 'NO_PROPOSAL_CHOSEN',
          status: 'FAIL',
          errorStep: 'INTEG_MISMATCH',
          description: 'Initiator proposed integrity ' + init.integ + ' but Responder configured with ' + resp.integ + '.',
          remediation: 'Align HMAC integrity transforms (e.g. AUTH_HMAC_SHA2_256_128).'
        };
      }
    }

    // 4. Check Diffie-Hellman Group
    if (init.dh !== resp.dh) {
      return {
        verdict: 'NO_PROPOSAL_CHOSEN',
        status: 'FAIL',
        errorStep: 'DH_GROUP_MISMATCH',
        description: 'Initiator proposed DH ' + init.dh + ' but Responder requires ' + resp.dh + '.',
        remediation: 'Align Diffie-Hellman groups for IKE_SA_INIT (e.g., Group 19 or Group 14).'
      };
    }

    // 5. Check Traffic Selectors (TSi / TSr CIDR ranges)
    if (init.localSubnet && resp.remoteSubnet && init.localSubnet !== resp.remoteSubnet) {
      return {
        verdict: 'TS_UNACCEPTABLE',
        status: 'FAIL',
        errorStep: 'TRAFFIC_SELECTOR_MISMATCH',
        description: 'Initiator local subnet ' + init.localSubnet + ' does not match Responder remote subnet ' + resp.remoteSubnet + '.',
        remediation: 'Ensure Phase 2 Child SA traffic selector CIDRs match or use Route-Based VPN (0.0.0.0/0).'
      };
    }

    // 6. Check NAT-Traversal / UDP 4500 requirement
    if (init.behindNat && !resp.natTraversalEnabled) {
      return {
        verdict: 'AUTHENTICATION_FAILED_TIMEOUT',
        status: 'FAIL',
        errorStep: 'NAT_TRAVERSAL_DISABLED',
        description: 'Initiator is behind NAT but Responder has NAT-Traversal (UDP 4500 encapsulation) disabled.',
        remediation: 'Enable NAT-T on Responder switch/firewall: "crypto ikev2 nat-traversal".'
      };
    }

    // 7. Successful Negotiation
    return {
      verdict: 'IKE_SA_ESTABLISHED',
      status: 'PASS',
      errorStep: 'NONE',
      description: 'All IKEv2 Phase 1 transforms, Phase 2 Child SA algorithms, and Traffic Selectors matched successfully.',
      establishedCipher: init.encr + ' / ' + init.prf + ' / ' + init.dh,
      saLifetimeSeconds: Math.min(init.lifetime || 86400, resp.lifetime || 86400)
    };
  }

  return {
    PAYLOAD_TYPES: PAYLOAD_TYPES,
    EXCHANGE_TYPES: EXCHANGE_TYPES,
    TRANSFORM_TYPES: TRANSFORM_TYPES,
    ENCR_IDS: ENCR_IDS,
    PRF_IDS: PRF_IDS,
    INTEG_IDS: INTEG_IDS,
    DH_IDS: DH_IDS,
    forgePacket: forgePacket,
    formatHexDump: formatHexDump,
    simulateNegotiation: simulateNegotiation
  };
});

/**
 * IPsecForge Pro - Web Application Controller
 * Connects protocol engine, cryptographic auditor, proposal matrix, and multi-platform synthesizer.
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  var currentPlatform = 'cisco';

  var PRESETS = {
    enterprise: {
      exchangeType: 34, // IKE_SA_INIT
      messageId: 0,
      spiInitiator: '4a82c9103e5b7f02',
      spiResponder: '0000000000000000',
      isResponse: false,
      initEncr: 'AES-GCM-256',
      initPrf: 'PRF_HMAC_SHA2_256',
      initInteg: 'NONE',
      initDh: 'Group 19 (256-bit ECP)',
      espEncr: 'AES-GCM-256',
      localSubnet: '10.100.0.0/16',
      remoteSubnet: '172.16.0.0/16',
      pfsEnabled: true,
      respEncr: 'AES-GCM-256',
      respPrf: 'PRF_HMAC_SHA2_256',
      respDh: 'Group 19 (256-bit ECP)',
      respRemoteSubnet: '10.100.0.0/16',
      respNatT: true,
      ikeVersion: 'IKEv2',
      antiReplayWindow: 256,
      dpdEnabled: true,
      dpdIntervalSec: 10,
      natTraversalEnabled: true,
      preSharedKey: 'K9x$mP4!wQ7#vL2*yR8@eZ5^bN3&uT1%',
      useCertificates: false
    },
    datacenter: {
      exchangeType: 34,
      messageId: 0,
      spiInitiator: '7b91d0234a6c8e11',
      spiResponder: '0000000000000000',
      isResponse: false,
      initEncr: 'AES-CBC-256',
      initPrf: 'PRF_HMAC_SHA2_256',
      initInteg: 'AUTH_HMAC_SHA2_256_128',
      initDh: 'Group 14 (2048-bit MODP)',
      espEncr: 'AES-CBC-256',
      localSubnet: '10.200.0.0/16',
      remoteSubnet: '192.168.10.0/24',
      pfsEnabled: true,
      respEncr: 'AES-CBC-256',
      respPrf: 'PRF_HMAC_SHA2_256',
      respDh: 'Group 14 (2048-bit MODP)',
      respRemoteSubnet: '10.200.0.0/16',
      respNatT: true,
      ikeVersion: 'IKEv2',
      antiReplayWindow: 256,
      dpdEnabled: true,
      dpdIntervalSec: 15,
      natTraversalEnabled: true,
      preSharedKey: 'H3l!oP9#qZ1$wE5*tY2@uI8^vB4%',
      useCertificates: false
    },
    legacy: {
      exchangeType: 34,
      messageId: 0,
      spiInitiator: '0102030405060708',
      spiResponder: '0000000000000000',
      isResponse: false,
      initEncr: '3DES-CBC',
      initPrf: 'PRF_HMAC_SHA1',
      initInteg: 'AUTH_HMAC_SHA1_96',
      initDh: 'Group 2 (1024-bit MODP)',
      espEncr: '3DES-CBC',
      localSubnet: '192.168.1.0/24',
      remoteSubnet: '10.0.0.0/24',
      pfsEnabled: false,
      respEncr: 'AES-CBC-256', // Intentionally mismatched to demonstrate negotiation failure!
      respPrf: 'PRF_HMAC_SHA1',
      respDh: 'Group 2 (1024-bit MODP)',
      respRemoteSubnet: '192.168.1.0/24',
      respNatT: false,
      ikeVersion: 'IKEv1',
      antiReplayWindow: 0,
      dpdEnabled: false,
      dpdIntervalSec: 60,
      natTraversalEnabled: false,
      preSharedKey: 'cisco123',
      useCertificates: false
    }
  };

  // DOM Elements
  var elExchangeType = document.getElementById('exchangeType');
  var elMessageId = document.getElementById('messageId');
  var elSpiInitiator = document.getElementById('spiInitiator');
  var elSpiResponder = document.getElementById('spiResponder');
  var elChkIsResponse = document.getElementById('chkIsResponse');

  var elInitEncr = document.getElementById('initEncr');
  var elInitPrf = document.getElementById('initPrf');
  var elInitInteg = document.getElementById('initInteg');
  var elInitDh = document.getElementById('initDh');

  var elEspEncr = document.getElementById('espEncr');
  var elLocalSubnet = document.getElementById('localSubnet');
  var elRemoteSubnet = document.getElementById('remoteSubnet');
  var elChkPfs = document.getElementById('chkPfs');

  var elRespEncr = document.getElementById('respEncr');
  var elRespPrf = document.getElementById('respPrf');
  var elRespDh = document.getElementById('respDh');
  var elRespRemoteSubnet = document.getElementById('respRemoteSubnet');
  var elChkRespNatT = document.getElementById('chkRespNatT');
  var elNegotiationResultBox = document.getElementById('negotiationResultBox');

  var elIkeVersion = document.getElementById('ikeVersion');
  var elAntiReplayWindow = document.getElementById('antiReplayWindow');
  var elChkDpd = document.getElementById('chkDpd');
  var elChkNatT = document.getElementById('chkNatT');
  var elPreSharedKey = document.getElementById('preSharedKey');
  var elChkCertAuth = document.getElementById('chkCertAuth');

  var elAuditSummaryBadge = document.getElementById('auditSummaryBadge');
  var elScorecardBanner = document.getElementById('scorecardBanner');
  var elGradeCircle = document.getElementById('gradeCircle');
  var elScorecardHeadline = document.getElementById('scorecardHeadline');
  var elScorecardSub = document.getElementById('scorecardSub');
  var elFindingsContainer = document.getElementById('findingsContainer');
  var elMatrixTableBody = document.getElementById('matrixTableBody');
  var elHexDumpDisplay = document.getElementById('hexDumpDisplay');
  var elConfigDisplay = document.getElementById('configDisplay');

  var btnCopyHex = document.getElementById('btnCopyHex');
  var btnCopyConfig = document.getElementById('btnCopyConfig');

  function getFormValues() {
    return {
      exchangeType: parseInt(elExchangeType.value, 10) || 34,
      messageId: parseInt(elMessageId.value, 10) || 0,
      spiInitiator: elSpiInitiator.value || '4a82c9103e5b7f02',
      spiResponder: elSpiResponder.value || '0000000000000000',
      isResponse: elChkIsResponse.checked,
      initEncr: elInitEncr.value,
      initPrf: elInitPrf.value,
      initInteg: elInitInteg.value,
      initDh: elInitDh.value,
      espEncr: elEspEncr.value,
      localSubnet: elLocalSubnet.value,
      remoteSubnet: elRemoteSubnet.value,
      pfsEnabled: elChkPfs.checked,
      respEncr: elRespEncr.value,
      respPrf: elRespPrf.value,
      respDh: elRespDh.value,
      respRemoteSubnet: elRespRemoteSubnet.value,
      respNatT: elChkRespNatT.checked,
      ikeVersion: elIkeVersion.value,
      antiReplayWindow: parseInt(elAntiReplayWindow.value, 10) || 0,
      antiReplayEnabled: parseInt(elAntiReplayWindow.value, 10) > 0,
      dpdEnabled: elChkDpd.checked,
      dpdIntervalSec: 10,
      natTraversalEnabled: elChkNatT.checked,
      preSharedKey: elPreSharedKey.value,
      useCertificates: elChkCertAuth.checked,
      encr: elInitEncr.value,
      prf: elInitPrf.value,
      dh: elInitDh.value
    };
  }

  function applyPreset(p) {
    elExchangeType.value = p.exchangeType;
    elMessageId.value = p.messageId;
    elSpiInitiator.value = p.spiInitiator;
    elSpiResponder.value = p.spiResponder;
    elChkIsResponse.checked = p.isResponse;

    elInitEncr.value = p.initEncr;
    elInitPrf.value = p.initPrf;
    elInitInteg.value = p.initInteg;
    elInitDh.value = p.initDh;

    elEspEncr.value = p.espEncr;
    elLocalSubnet.value = p.localSubnet;
    elRemoteSubnet.value = p.remoteSubnet;
    elChkPfs.checked = p.pfsEnabled;

    elRespEncr.value = p.respEncr;
    elRespPrf.value = p.respPrf;
    elRespDh.value = p.respDh;
    elRespRemoteSubnet.value = p.respRemoteSubnet;
    elChkRespNatT.checked = p.respNatT;

    elIkeVersion.value = p.ikeVersion;
    elAntiReplayWindow.value = p.antiReplayWindow;
    elChkDpd.checked = p.dpdEnabled;
    elChkNatT.checked = p.natTraversalEnabled;
    elPreSharedKey.value = p.preSharedKey;
    elChkCertAuth.checked = p.useCertificates;

    updateUI();
  }

  function renderMatrixTable(vals) {
    var rows = [
      { name: 'Phase 1 Encryption (ENCR)', init: vals.initEncr, resp: vals.respEncr, match: vals.initEncr === vals.respEncr },
      { name: 'Pseudo-Random Function (PRF)', init: vals.initPrf, resp: vals.respPrf, match: vals.initPrf === vals.respPrf },
      { name: 'Diffie-Hellman Group (D-H)', init: vals.initDh, resp: vals.respDh, match: vals.initDh === vals.respDh },
      { name: 'Traffic Selector Subnet', init: vals.localSubnet, resp: vals.respRemoteSubnet, match: vals.localSubnet === vals.respRemoteSubnet },
      { name: 'NAT-Traversal (UDP 4500)', init: vals.natTraversalEnabled ? 'Enabled' : 'Disabled', resp: vals.respNatT ? 'Enabled' : 'Disabled', match: (!vals.natTraversalEnabled || vals.respNatT) }
    ];

    elMatrixTableBody.innerHTML = '';
    rows.forEach(function (r) {
      var tr = document.createElement('tr');
      var statusBadge = r.match
        ? '<span class="badge badge-emerald" style="padding:2px 6px;">MATCH</span>'
        : '<span class="badge badge-rose" style="padding:2px 6px; background:rgba(244,63,94,0.15); color:#fb7185; border-color:rgba(244,63,94,0.3);">MISMATCH</span>';

      tr.innerHTML = '<td><strong>' + r.name + '</strong></td>' +
        '<td>' + r.init + '</td>' +
        '<td>' + r.resp + '</td>' +
        '<td>' + statusBadge + '</td>';
      elMatrixTableBody.appendChild(tr);
    });
  }

  function updateUI() {
    var vals = getFormValues();

    // 1. Live Negotiation Simulation
    var negResult = IKEv2ProtocolEngine.simulateNegotiation(
      { encr: vals.initEncr, prf: vals.initPrf, integ: vals.initInteg, dh: vals.initDh, localSubnet: vals.localSubnet, behindNat: vals.natTraversalEnabled },
      { encr: vals.respEncr, prf: vals.respPrf, dh: vals.respDh, remoteSubnet: vals.respRemoteSubnet, natTraversalEnabled: vals.respNatT }
    );

    if (negResult.status === 'PASS') {
      elNegotiationResultBox.className = 'sim-box sim-box-permit';
      elNegotiationResultBox.innerHTML = '<div><strong>Negotiation Verdict:</strong> ' + negResult.verdict + ' (SUCCESS)</div>' +
        '<div><strong>Details:</strong> ' + negResult.description + '</div>' +
        '<div><strong>Established Suite:</strong> ' + negResult.establishedCipher + '</div>';
    } else {
      elNegotiationResultBox.className = 'sim-box sim-box-deny';
      elNegotiationResultBox.innerHTML = '<div><strong>Negotiation Verdict:</strong> ' + negResult.verdict + ' (' + negResult.errorStep + ')</div>' +
        '<div><strong>Details:</strong> ' + negResult.description + '</div>' +
        '<div style="color:#fbbf24;"><strong>Remediation:</strong> ' + negResult.remediation + '</div>';
    }

    // 2. Proposal Matrix Table
    renderMatrixTable(vals);

    // 3. Binary Wireframe Encoding & Hex Dump
    var forged = IKEv2ProtocolEngine.forgePacket({
      exchangeType: vals.exchangeType,
      messageId: vals.messageId,
      spiInitiator: vals.spiInitiator,
      spiResponder: vals.spiResponder,
      isResponse: vals.isResponse,
      encr: vals.initEncr,
      prf: vals.initPrf,
      integ: vals.initInteg,
      dh: vals.initDh
    });

    var dumpText = IKEv2ProtocolEngine.formatHexDump(forged.rawBytes);
    var banner = '[RFC 7296 ' + forged.exchangeName + ' | Initiator SPI: 0x' + forged.initiatorSpiHex + ' | Responder SPI: 0x' + forged.responderSpiHex + ' | Payloads: SA, KE, Nonce | Length: ' + forged.totalLength + ' Bytes]\n\n';
    elHexDumpDisplay.textContent = banner + dumpText;

    // 4. Security Audit Evaluation
    var audit = IPsecCryptoAuditor.auditConfiguration(vals);
    elAuditSummaryBadge.textContent = audit.score + ' / 100 PTS (' + audit.grade + ')';
    elGradeCircle.textContent = audit.grade;

    if (audit.grade === 'F' || audit.grade === 'C') {
      elScorecardBanner.className = 'scorecard-banner fail-banner';
      elGradeCircle.className = 'grade-circle fail-circle';
      elAuditSummaryBadge.className = 'badge badge-gold';
      elScorecardHeadline.textContent = 'High Cryptographic Risk Exposure (Grade ' + audit.grade + ')';
      elScorecardSub.textContent = audit.failCount + ' critical security findings detected. Vulnerable to precomputation attacks, offline cracking, and lack of PFS.';
    } else {
      elScorecardBanner.className = 'scorecard-banner';
      elGradeCircle.className = 'grade-circle';
      elAuditSummaryBadge.className = 'badge badge-emerald';
      elScorecardHeadline.textContent = 'Zero-Trust IPsec Policy Compliance (Grade ' + audit.grade + ')';
      elScorecardSub.textContent = audit.passCount + '/10 controls passed. Modern IKEv2, AEAD GCM confidentiality, Elliptic Curve D-H, and active DPD.';
    }

    // Render findings
    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(function (f) {
      var item = document.createElement('div');
      item.className = 'finding-item';

      var scoreColor = f.status === 'PASS' ? '#34d399' : (f.status === 'WARNING' ? '#fbbf24' : '#fb7185');
      var statusIcon = f.status === 'PASS' ? '✓' : (f.status === 'WARNING' ? '⚠' : '✗');

      item.innerHTML = '<div class="finding-top">' +
        '<div class="finding-title" style="color:' + scoreColor + '">' + statusIcon + ' ' + f.title + '</div>' +
        '<div class="finding-score" style="color:' + scoreColor + '">' + f.earned + ' / ' + f.weight + ' pts</div>' +
        '</div>' +
        '<div class="finding-text">' + f.details + '</div>' +
        '<div class="finding-remediation">Remediation: ' + f.remediation + '</div>';
      elFindingsContainer.appendChild(item);
    });

    // 5. Synthesize Configurations
    renderPlatformConfig(vals);
  }

  function renderPlatformConfig(vals) {
    vals = vals || getFormValues();
    var synthesized = '';
    if (currentPlatform === 'cisco') {
      synthesized = IPsecConfigSynthesizer.synthesizeCisco(vals);
    } else if (currentPlatform === 'strongswan') {
      synthesized = IPsecConfigSynthesizer.synthesizeStrongswan(vals);
    } else if (currentPlatform === 'fortinet') {
      synthesized = IPsecConfigSynthesizer.synthesizeFortinet(vals);
    } else if (currentPlatform === 'paloalto') {
      synthesized = IPsecConfigSynthesizer.synthesizePaloAlto(vals);
    } else if (currentPlatform === 'aws') {
      synthesized = IPsecConfigSynthesizer.synthesizeAws(vals);
    } else if (currentPlatform === 'prometheus') {
      synthesized = IPsecConfigSynthesizer.synthesizePrometheus(vals);
    }
    elConfigDisplay.textContent = synthesized;
  }

  // Event Listeners
  var inputs = [
    elExchangeType, elMessageId, elSpiInitiator, elSpiResponder, elChkIsResponse,
    elInitEncr, elInitPrf, elInitInteg, elInitDh,
    elEspEncr, elLocalSubnet, elRemoteSubnet, elChkPfs,
    elRespEncr, elRespPrf, elRespDh, elRespRemoteSubnet, elChkRespNatT,
    elIkeVersion, elAntiReplayWindow, elChkDpd, elChkNatT, elPreSharedKey, elChkCertAuth
  ];

  inputs.forEach(function (inp) {
    if (!inp) return;
    inp.addEventListener('input', updateUI);
    inp.addEventListener('change', updateUI);
  });

  // Preset Buttons
  document.getElementById('btnPresetEnterprise').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.enterprise);
  });

  document.getElementById('btnPresetDatacenter').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.datacenter);
  });

  document.getElementById('btnPresetLegacy').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.legacy);
  });

  // Copy Buttons
  btnCopyHex.addEventListener('click', function () {
    navigator.clipboard.writeText(elHexDumpDisplay.textContent).then(function () {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(function () { btnCopyHex.textContent = 'Copy Hex Dump'; }, 2000);
    });
  });

  btnCopyConfig.addEventListener('click', function () {
    navigator.clipboard.writeText(elConfigDisplay.textContent).then(function () {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(function () { btnCopyConfig.textContent = 'Copy Configuration'; }, 2000);
    });
  });

  // Platform Tabs
  document.querySelectorAll('.tabs-nav .tab-btn').forEach(function (tab) {
    tab.addEventListener('click', function () {
      document.querySelectorAll('.tabs-nav .tab-btn').forEach(function (t) { t.classList.remove('active'); });
      this.classList.add('active');
      currentPlatform = this.getAttribute('data-platform');
      renderPlatformConfig();
    });
  });

  // Initial Run
  applyPreset(PRESETS.enterprise);
});

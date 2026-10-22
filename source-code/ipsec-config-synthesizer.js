/**
 * IPsecForge Pro - Multi-Platform Configuration Synthesizer
 * Generates production-ready, hardened IKEv2 and IPsec ESP configurations for
 * Cisco IOS-XE, Linux StrongSwan, Fortinet FortiOS, Palo Alto PAN-OS, AWS VPN, and Prometheus.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IPsecConfigSynthesizer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function mapCiscoDh(dhStr) {
    if (dhStr.indexOf('19') !== -1) return '19';
    if (dhStr.indexOf('20') !== -1) return '20';
    if (dhStr.indexOf('21') !== -1) return '21';
    if (dhStr.indexOf('14') !== -1) return '14';
    return '19';
  }

  function mapCiscoEncr(encrStr) {
    if (encrStr.indexOf('AES-GCM-256') !== -1) return 'aes-gcm-256';
    if (encrStr.indexOf('AES-GCM-128') !== -1) return 'aes-gcm-128';
    if (encrStr.indexOf('AES-CBC-256') !== -1) return 'aes-cbc-256';
    return 'aes-gcm-256';
  }

  function synthesizeCisco(cfg) {
    var peerIp = cfg.remoteGatewayIp || '198.51.100.1';
    var localIp = cfg.localGatewayIp || '203.0.113.1';
    var psk = cfg.preSharedKey || 'K9x$mP4!wQ7#vL2*yR8@eZ5^bN3&uT1%';
    var dh = mapCiscoDh(cfg.dh || 'Group 19 (256-bit ECP)');
    var encr = mapCiscoEncr(cfg.encr || 'AES-GCM-256');
    var isAead = encr.indexOf('gcm') !== -1;

    var out = [];
    out.push('! =================================================================');
    out.push('! Cisco IOS-XE / Catalyst 8000 Production IKEv2 Route-Based IPsec');
    out.push('! Standards: RFC 7296 (IKEv2) | RFC 4303 (ESP) | NIST SP 800-77 R1');
    out.push('! =================================================================');
    out.push('!');
    out.push('! --- Phase 1: IKEv2 Proposal & Policy ---');
    out.push('crypto ikev2 proposal PROPOSAL-IPSECFORGE');
    out.push(' encryption ' + encr);
    if (!isAead) out.push(' integrity sha256');
    out.push(' prf sha256');
    out.push(' group ' + dh);
    out.push('!');
    out.push('crypto ikev2 policy POLICY-IPSECFORGE');
    out.push(' proposal PROPOSAL-IPSECFORGE');
    out.push('!');
    out.push('! --- IKEv2 Keyring & Pre-Shared Key ---');
    out.push('crypto ikev2 keyring KEYRING-IPSECFORGE');
    out.push(' peer CLOUD-GATEWAY');
    out.push('  address ' + peerIp);
    out.push('  pre-shared-key ' + psk);
    out.push('!');
    out.push('! --- IKEv2 Profile with DPD & Anti-Replay ---');
    out.push('crypto ikev2 profile PROFILE-IPSECFORGE');
    out.push(' match address local ' + localIp);
    out.push(' match identity remote address ' + peerIp + ' 255.255.255.255');
    out.push(' identity local address ' + localIp);
    out.push(' authentication remote pre-share');
    out.push(' authentication local pre-share');
    out.push(' keyring local KEYRING-IPSECFORGE');
    out.push(' dpd 10 3 periodic');
    out.push('!');
    out.push('! --- Phase 2: IPsec Transform-Set & Profile ---');
    if (isAead) {
      out.push('crypto ipsec transform-set TS-IPSECFORGE esp-gcm 256');
    } else {
      out.push('crypto ipsec transform-set TS-IPSECFORGE esp-aes 256 esp-sha256-hmac');
    }
    out.push(' mode tunnel');
    out.push('!');
    out.push('crypto ipsec profile IPSEC-PROFILE-IPSECFORGE');
    out.push(' set transform-set TS-IPSECFORGE');
    out.push(' set ikev2-profile PROFILE-IPSECFORGE');
    out.push(' set pfs group' + dh);
    out.push('!');
    out.push('! --- Route-Based Virtual Tunnel Interface (VTI) ---');
    out.push('interface Tunnel100');
    out.push(' description Route-Based IPsec Tunnel to Cloud Core');
    out.push(' ip address 169.254.10.2 255.255.255.252');
    out.push(' ip mtu 1438');
    out.push(' ip tcp adjust-mss 1379');
    out.push(' tunnel source ' + localIp);
    out.push(' tunnel mode ipsec ipv4');
    out.push(' tunnel destination ' + peerIp);
    out.push(' tunnel protection ipsec profile IPSEC-PROFILE-IPSECFORGE');
    out.push('!');
    out.push('crypto ipsec security-association replay window-size 256');
    return out.join('\n');
  }

  function synthesizeStrongswan(cfg) {
    var peerIp = cfg.remoteGatewayIp || '198.51.100.1';
    var localIp = cfg.localGatewayIp || '203.0.113.1';
    var psk = cfg.preSharedKey || 'K9x$mP4!wQ7#vL2*yR8@eZ5^bN3&uT1%';

    var out = [];
    out.push('# =================================================================');
    out.push('# Linux StrongSwan Modern Syntax (swanctl.conf)');
    out.push('# Standards: RFC 7296 IKEv2 | AEAD GCM | Route-Based / VTI');
    out.push('# =================================================================');
    out.push('connections {');
    out.push('    cloud-interconnect {');
    out.push('        version = 2');
    out.push('        local_addrs = ' + localIp);
    out.push('        remote_addrs = ' + peerIp);
    out.push('        proposals = aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048');
    out.push('        dpd_delay = 10s');
    out.push('        dpd_timeout = 30s');
    out.push('        local {');
    out.push('            auth = psk');
    out.push('            id = ' + localIp);
    out.push('        }');
    out.push('        remote {');
    out.push('            auth = psk');
    out.push('            id = ' + peerIp);
    out.push('        }');
    out.push('        children {');
    out.push('            net-to-net {');
    out.push('                local_ts = 10.100.0.0/16');
    out.push('                remote_ts = 172.16.0.0/16');
    out.push('                esp_proposals = aes256gcm16-ecp256,aes256-sha256-modp2048');
    out.push('                start_action = start');
    out.push('                dpd_action = restart');
    out.push('                rekey_time = 3600s');
    out.push('            }');
    out.push('        }');
    out.push('    }');
    out.push('}');
    out.push('');
    out.push('secrets {');
    out.push('    ike-cloud {');
    out.push('        id-peer = ' + peerIp);
    out.push('        secret = "' + psk + '"');
    out.push('    }');
    out.push('}');
    return out.join('\n');
  }

  function synthesizeFortinet(cfg) {
    var peerIp = cfg.remoteGatewayIp || '198.51.100.1';
    var psk = cfg.preSharedKey || 'K9x$mP4!wQ7#vL2*yR8@eZ5^bN3&uT1%';

    var out = [];
    out.push('# =================================================================');
    out.push('# Fortinet FortiOS Hardened IKEv2 Route-Based IPsec Tunnel');
    out.push('# =================================================================');
    out.push('config vpn ipsec phase1-interface');
    out.push('    edit "IPSec-Cloud"');
    out.push('        set interface "wan1"');
    out.push('        set ike-version 2');
    out.push('        set keylife 86400');
    out.push('        set peertype any');
    out.push('        set proposal aes256gcm-prfsha256 aes256-sha256');
    out.push('        set dhgrp 19 14');
    out.push('        set remote-gw ' + peerIp);
    out.push('        set psksecret "' + psk + '"');
    out.push('        set dpd-retryinterval 10');
    out.push('        set dpd on-idle');
    out.push('    next');
    out.push('end');
    out.push('!');
    out.push('config vpn ipsec phase2-interface');
    out.push('    edit "IPSec-Cloud-P2"');
    out.push('        set phase1name "IPSec-Cloud"');
    out.push('        set proposal aes256gcm aes256-sha256');
    out.push('        set dhgrp 19 14');
    out.push('        set keylifeseconds 3600');
    out.push('        set auto-negotiate enable');
    out.push('    next');
    out.push('end');
    return out.join('\n');
  }

  function synthesizePaloAlto(cfg) {
    var peerIp = cfg.remoteGatewayIp || '198.51.100.1';
    var psk = cfg.preSharedKey || 'K9x$mP4!wQ7#vL2*yR8@eZ5^bN3&uT1%';

    var out = [];
    out.push('# =================================================================');
    out.push('# Palo Alto Networks PAN-OS IKEv2 / IPsec Configuration');
    out.push('# =================================================================');
    out.push('set network ike crypto-profiles ike-crypto-profile IKE-PROF-PRO hash sha256 dh-group group19 encryption aes-256-gcm lifetime hours 24');
    out.push('set network ike gateway IKE-GW-PRO authentication pre-shared-key key "' + psk + '"');
    out.push('set network ike gateway IKE-GW-PRO protocol ikev2 ikev2-crypto-profile IKE-PROF-PRO');
    out.push('set network ike gateway IKE-GW-PRO protocol-common nat-traversal enable yes');
    out.push('set network ike gateway IKE-GW-PRO protocol-common fragmentation enable yes');
    out.push('set network ike gateway IKE-GW-PRO peer-address ip ' + peerIp);
    out.push('!');
    out.push('set network ipsec crypto-profiles ipsec-crypto-profile IPSEC-PROF-PRO esp encryption aes-256-gcm dh-group group19 lifetime hours 1');
    out.push('set network tunnel ipsec IPSEC-TUNNEL-PRO auto-key ike-gateway IKE-GW-PRO ipsec-crypto-profile IPSEC-PROF-PRO tunnel-interface tunnel.1');
    return out.join('\n');
  }

  function synthesizeAws(cfg) {
    var out = [];
    out.push('# =================================================================');
    out.push('# AWS Site-to-Site VPN Customer Gateway Specification Stanza');
    out.push('# VPC Virtual Private Gateway / Transit Gateway Attachment');
    out.push('# =================================================================');
    out.push('Amazon Web Services Site-to-Site VPN Configuration Template:');
    out.push('  - IPsec Protocol: IKEv2 (RFC 7296)');
    out.push('  - Phase 1 (IKE SA):');
    out.push('      Encryption: AES-256-GCM / AES-256-CBC');
    out.push('      Integrity: SHA-256');
    out.push('      Diffie-Hellman Group: Group 19 (ECP P-256) or Group 14 (MODP 2048)');
    out.push('      Lifetime: 28,800 seconds (8 hours)');
    out.push('  - Phase 2 (Child SA / ESP):');
    out.push('      Protocol: ESP');
    out.push('      Encryption: AES-256-GCM');
    out.push('      Perfect Forward Secrecy (PFS): Group 19 or Group 14');
    out.push('      Lifetime: 3,600 seconds (1 hour)');
    out.push('  - Keepalive & Traversal:');
    out.push('      DPD Timeout: 30 seconds (Action: restart)');
    out.push('      NAT-T: UDP port 4500 enabled');
    return out.join('\n');
  }

  function synthesizePrometheus(cfg) {
    var out = [];
    out.push('# =================================================================');
    out.push('# Prometheus IPsec Tunnel & Security Association Alerting Rules');
    out.push('# =================================================================');
    out.push('groups:');
    out.push('  - name: ipsec_vpn_tunnel_alerts');
    out.push('    rules:');
    out.push('      - alert: IPsecTunnelDown');
    out.push('        expr: ipsec_tunnel_status{peer=~".+"} == 0');
    out.push('        for: 30s');
    out.push('        labels:');
    out.push('          severity: critical');
    out.push('        annotations:');
    out.push('          summary: "IPsec Site-to-Site VPN Tunnel Down"');
    out.push('          description: "Gateway {{ $labels.instance }} lost IPsec SA connection with peer {{ $labels.peer }}."');
    out.push('');
    out.push('      - alert: IKEv2ProposalMismatchDetected');
    out.push('        expr: rate(cisco_ikev2_proposal_mismatch_drops[5m]) > 0');
    out.push('        labels:');
    out.push('          severity: warning');
    out.push('        annotations:');
    out.push('          summary: "IKEv2 Phase 1 Proposal Mismatch (NO_PROPOSAL_CHOSEN)"');
    out.push('          description: "IKEv2 SA negotiations failed due to cryptographic cipher or DH group mismatch."');
    out.push('');
    out.push('      - alert: IPsecAntiReplayPacketDrops');
    out.push('        expr: rate(cisco_ipsec_replay_packet_drops[5m]) > 5');
    out.push('        labels:');
    out.push('          severity: warning');
    out.push('        annotations:');
    out.push('          summary: "Spike in dropped replayed IPsec packets"');
    out.push('          description: "Anti-replay window on {{ $labels.instance }} is dropping duplicate sequence numbers."');
    return out.join('\n');
  }

  return {
    synthesizeCisco: synthesizeCisco,
    synthesizeStrongswan: synthesizeStrongswan,
    synthesizeFortinet: synthesizeFortinet,
    synthesizePaloAlto: synthesizePaloAlto,
    synthesizeAws: synthesizeAws,
    synthesizePrometheus: synthesizePrometheus
  };
});

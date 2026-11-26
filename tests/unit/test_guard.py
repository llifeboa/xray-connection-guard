#!/usr/bin/env python3
import copy
import datetime as dt
import json
import os
import queue
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import guard as g


def settings(audit):
    return {
        'eve':{'type':'file','path':'/tmp/nonexistent'},
        'access':{'type':'file','path':'/tmp/nonexistent'},
        'xray_timezone':'UTC', 'signatures':[9100001],
        'min_distinct_peers':5,'min_distinct_flows':5,
        'max_match_delay_seconds':60,'correlation_buffer_seconds':0,
        'window_seconds':300,'audit_path':str(audit),
        'firewall':{'host_network':True,
                    'ban_seconds':600,'allowlist_cidrs':['198.51.100.0/24']}
    }


class FakeFirewall(g.Firewall):
    def __init__(self, cfg, servers):
        super().__init__(cfg, servers)
        self.bans=[]
    def allowed_to_ban(self, ip):
        # Documentation-only clients are non-global. Permit them only in this
        # test double; the production public-address policy is tested below.
        if ip in {'203.0.113.20', '203.0.113.30', '2001:db8:4::20'}:
            address = g.ipaddress.ip_address(ip)
            return ip not in self.server_ips and not any(address in net for net in self.allow)
        return super().allowed_to_ban(ip)
    def ban(self, ip):
        self.bans.append(ip)
        return [{'scope':'all','ok':True}]


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg=settings(Path(self.tmp.name)/'audit.jsonl')
        g.validate(self.cfg)
        self.srv={'192.0.2.10'}
        self.fw=FakeFirewall(self.cfg['firewall'],self.srv)
        self.c=g.Correlator(self.cfg,self.srv,'enforce',self.fw)
        self.ts=time.time()

    def access(self, peer_ip, peer_port, user='client-a@example.test', client='203.0.113.20'):
        t=dt.datetime.fromtimestamp(self.ts,dt.timezone.utc).strftime('%Y/%m/%d %H:%M:%S.%f')
        line=f'{t} from tcp:{client}:62450 accepted udp:{peer_ip}:{peer_port} [VLESS TCP REALITY >> DIRECT] email: {user}'
        self.c.add_access(line)

    def event(self, peer_ip, peer_port, flow, user='client-a@example.test', client='203.0.113.20'):
        self.access(peer_ip,peer_port,user,client)
        self.c.evaluate({'ts':self.ts+1,'proto':'UDP','peer':(peer_ip,peer_port),
                          'flow':str(flow),'sid':9100001})

    def eve(self, peer_ip, peer_port, flow):
        return json.dumps({
            'event_type':'alert',
            'timestamp':dt.datetime.fromtimestamp(self.ts+1,dt.timezone.utc).isoformat(),
            'alert':{'action':'blocked','signature_id':9100001},
            'src_ip':'192.0.2.10','src_port':50000,
            'dest_ip':peer_ip,'dest_port':peer_port,'proto':'UDP','flow_id':flow,
        })

    def test_late_access_records_are_correlated_without_repeated_alerts(self):
        self.cfg['correlation_buffer_seconds']=3
        with mock.patch.object(g.time,'monotonic',return_value=1000):
            for i in range(5):
                self.c.add_eve(self.eve(f'198.51.100.{i+1}',31000+i,i))
        with mock.patch.object(g.time,'monotonic',return_value=1004):
            self.c.process_pending()
        self.assertEqual(self.fw.bans,[])
        self.assertFalse(self.c.seen_flows)
        for i in range(5):
            self.access(f'198.51.100.{i+1}',31000+i)
        with mock.patch.object(g.time,'monotonic',return_value=1005):
            self.c.process_pending()
        self.assertEqual(self.fw.bans,['203.0.113.20'])
        self.assertEqual(self.c.stats['matched'],5)
        self.assertFalse(self.c.pending)
        self.assertFalse(self.c.pending_flows)

    def test_suricata_timestamps_and_reverse_alert_keep_flow_start(self):
        payload = {
            'timestamp': '2025-01-15T12:01:35.000000+0000',
            'flow_id': 10001, 'event_type': 'alert',
            'src_ip': '198.51.100.12', 'src_port': 31000,
            'dest_ip': '192.0.2.20', 'dest_port': 41000, 'proto': 'UDP',
            'alert': {'action': 'blocked', 'signature_id': 9100001},
            'flow': {'start': '2025-01-15T12:00:00.000000+0000'},
        }
        event = g.get_peer_alert(payload, {'192.0.2.20'}, {9100001})
        self.assertIsNotNone(event)
        self.assertEqual(event['peer'], ('198.51.100.12', 31000))
        self.assertAlmostEqual(event['ts'] - event['flow_start_ts'], 95.0, places=5)
        self.srv.add('192.0.2.20')
        self.ts = event['flow_start_ts']
        self.access('198.51.100.12', 31000)
        self.assertTrue(self.c.evaluate(event))
        self.assertEqual(self.c.stats['matched'], 1)

    def test_late_ndpi_classification_still_bans_after_five_recent_detections(self):
        detected = self.ts
        for i, age in enumerate((95, 301, 130, 350, 200)):
            self.ts = detected - age
            peer, port = f'198.51.100.{i + 1}', 31000 + i
            self.access(peer, port)
            payload = json.loads(self.eve(peer, port, i))
            payload['timestamp'] = dt.datetime.fromtimestamp(
                detected, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
            payload['flow'] = {'start': dt.datetime.fromtimestamp(
                self.ts, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')}
            self.c.add_eve(json.dumps(payload))
            with self.assertLogs(g.LOG, 'INFO'):
                self.c.process_pending()
            self.assertEqual(len(self.fw.bans), 1 if i == 4 else 0)
        self.assertEqual(self.c.stats['matched'], 5)
        self.assertEqual(self.fw.bans, ['203.0.113.20'])
        self.assertEqual(self.c.stats['bans'], 1)

    def test_flow_start_selects_original_client_instead_of_later_peer_visitor(self):
        started = self.ts
        self.access('198.51.100.1', 31000)
        self.ts += 94
        self.access('198.51.100.1', 31000, user='later', client='203.0.113.30')
        payload = json.loads(self.eve('198.51.100.1', 31000, 1))
        payload['flow'] = {'start': dt.datetime.fromtimestamp(
            started, dt.timezone.utc).isoformat()}
        self.c.add_eve(json.dumps(payload))
        with self.assertLogs(g.LOG, 'INFO'):
            self.c.process_pending()
        self.assertEqual(self.c.stats['matched'], 1)
        self.assertIn('203.0.113.20', self.c.events)
        self.assertNotIn('203.0.113.30', self.c.events)

    def test_missing_or_invalid_flow_start_falls_back_to_alert_time(self):
        original = json.loads(self.eve('198.51.100.1', 31000, 1))
        for flow in (None, [], {}, {'start': None}, {'start': 'invalid'},
                     {'start': dt.datetime.fromtimestamp(
                         self.ts + 100, dt.timezone.utc).isoformat()}):
            with self.subTest(flow=flow):
                event = g.get_peer_alert(dict(original, flow=flow), self.srv, {9100001})
                self.assertIsNotNone(event)
                self.assertEqual(event['flow_start_ts'], event['ts'])

    def test_compact_timezone_offsets_have_the_correct_utc_time(self):
        expected = g.timestamp('2025-01-15T12:00:00.000000Z')
        for value in ('2025-01-15T12:00:00.000000+0000',
                      '2025-01-15T17:30:00.000000+0530',
                      '2025-01-15T08:30:00.000000-0330'):
            with self.subTest(value=value):
                self.assertEqual(g.timestamp(value), expected)

    def udp_open(self, port=42000, peer='198.51.100.10:6881', session='20001', local='[::]'):
        stamp = dt.datetime.fromtimestamp(self.ts, g.UTC).strftime('%Y/%m/%d %H:%M:%S.%f')
        self.c.add_access(f'{stamp} [Info] [{session}] proxy/freedom: connection opened to '
                          f'udp:{peer}, local endpoint {local}:{port}, remote endpoint {peer}')

    def udp_event(self, peer='198.51.100.11', port=42000, flow=10002):
        payload = json.loads(self.eve(peer, 32000, flow))
        payload['src_port'] = port
        payload['flow'] = {'start': dt.datetime.fromtimestamp(self.ts, g.UTC).isoformat()}
        return g.get_peer_alert(payload, self.srv, {9100001})

    def test_xudp_changes_peer_minutes_after_socket_open(self):
        self.ts = g.timestamp('2025-01-15T12:00:00.000500Z')
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            # The INFO record arrived before its earlier-timestamped access record.
            self.udp_open()
            self.c.add_access('2025/01/15 12:00:00.000100 from tcp:203.0.113.20:51000 '
                              'accepted udp:198.51.100.10:6881 [TEST-IN >> DIRECT] email: client-b@example.test')
            self.c.process_pending()
            self.ts = g.timestamp('2025-01-15T12:03:15.000000Z')
            event = self.udp_event()
            self.assertTrue(self.c.evaluate(event))
        self.assertEqual(self.c.stats['matched_by_udp_socket'], 1)
        evidence = self.c.events['203.0.113.20'][0]
        self.assertEqual(evidence['emails'], ('client-b@example.test',))
        self.assertEqual(evidence['peer'], ('198.51.100.11', 32000))
        self.assertEqual(evidence['local'], ('192.0.2.10', 42000))
        self.assertEqual(self.fw.bans, [])  # Repeated alerts for one flow do not reach five.

    def test_one_xudp_socket_with_five_unlogged_peers_bans_after_long_delay(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.access('198.51.100.10', 6881, user='client-b@example.test')
            self.udp_open()
            self.c.process_pending()
            self.ts += 7200
            self.c.process_pending()  # Drop short-lived access history, keep the live socket owner.
            self.assertFalse(self.c.access)
            for i in range(5):
                self.assertTrue(self.c.evaluate(self.udp_event(f'198.51.100.{i + 1}', flow=i)))
        self.assertEqual(self.c.stats['matched_by_udp_socket'], 5)
        self.assertEqual(self.fw.bans, ['203.0.113.20'])
        self.assertEqual(json.loads(Path(self.cfg['audit_path']).read_text())['email'], 'client-b@example.test')

    def test_tcp_info_with_the_same_port_does_not_bind_a_udp_socket(self):
        self.access('198.51.100.10', 6881)
        stamp = dt.datetime.fromtimestamp(self.ts, g.UTC).strftime('%Y/%m/%d %H:%M:%S.%f')
        self.c.add_access(f'{stamp} [Info] [20002] proxy/freedom: connection opened to '
                          'tcp:www.example.test:80, local endpoint [2001:db8:1::1]:42000, '
                          'remote endpoint [2001:db8:3::80]:80')
        self.assertFalse(self.c.evaluate(self.udp_event()))
        self.assertFalse(self.c.udp.entries)

    def test_closed_or_recycled_udp_inode_never_keeps_the_old_owner(self):
        for sockets in ({}, {('::', 42000): {456}}, {('::', 42000): {123, 456}},
                        {('::', 42000): {123}, ('0.0.0.0', 42000): {456}}):
            with self.subTest(sockets=sockets), \
                 mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}) as probe, \
                 mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
                self.c.udp.entries.clear()
                self.c.udp.by_peer.clear()
                self.access('198.51.100.10', 6881)
                self.udp_open()
                self.c.udp.refresh(force=True)
                probe.return_value = sockets
                self.assertFalse(self.c.evaluate(self.udp_event()))
        self.assertEqual(self.c.stats['matched_by_udp_socket'], 0)

    def test_new_udp_generation_does_not_claim_an_old_flow(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}) as probe, \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.access('198.51.100.10', 6881)
            self.udp_open()
            self.c.udp.refresh(force=True)
            old_event = self.udp_event()
            self.ts += 1  # Even a port reused within three seconds is a different generation.
            self.access('198.51.100.99', 6881, client='203.0.113.30', user='other')
            self.udp_open(peer='198.51.100.99:6881', session='123456')
            probe.return_value = {('::', 42000): {456}}
            self.assertFalse(self.c.evaluate(old_event))
            self.assertTrue(self.c.evaluate(self.udp_event(flow=2)))
        self.assertNotIn('203.0.113.20', self.c.events)
        self.assertIn('203.0.113.30', self.c.events)

    def test_late_access_for_socket_and_conflicting_peer_record_use_socket_owner(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.udp_open()
            self.c.udp.refresh(force=True)
            event = self.udp_event()
            self.assertFalse(self.c.evaluate(event))
            self.access('198.51.100.10', 6881)
            self.access('198.51.100.11', 32000, client='203.0.113.30')
            self.assertTrue(self.c.evaluate(event))
        self.assertIn('203.0.113.20', self.c.events)
        self.assertNotIn('203.0.113.30', self.c.events)

    def test_ambiguous_initial_socket_owner_stays_ambiguous_after_history_expires(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.access('198.51.100.10', 6881)
            self.access('198.51.100.10', 6881, client='203.0.113.30', user='other')
            self.udp_open()
            self.c.process_pending()
            self.ts += 1000
            self.c.process_pending()
            self.assertFalse(self.c.access)
            self.assertFalse(self.c.evaluate(self.udp_event()))

    def test_ipv6_and_reverse_events_share_a_dual_stack_udp_socket(self):
        self.srv.add('2001:db8:1::1')
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.access('198.51.100.10', 6881)
            self.udp_open()
            self.c.process_pending()
            payload = json.loads(self.eve('198.51.100.1', 1234, 77))
            payload.update(src_ip='2001:0db8:0002:0000:0000:0000:0000:0001', src_port=33000,
                           dest_ip='2001:0db8:0001:0000:0000:0000:0000:0001', dest_port=42000)
            event = g.get_peer_alert(payload, self.srv, {9100001})
            self.assertTrue(self.c.evaluate(event))
            self.assertEqual(event['local'], ('2001:db8:1::1', 42000))
            self.assertEqual(event['peer'], ('2001:db8:2::1', 33000))

    def test_proc_read_failure_disables_socket_matching_until_verified_again(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}) as probe, \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            self.access('198.51.100.10', 6881)
            self.udp_open()
            self.c.process_pending()
            probe.side_effect = OSError('unavailable')
            with self.assertLogs(g.LOG, 'WARNING'):
                self.assertFalse(self.c.evaluate(self.udp_event()))
            self.assertEqual(self.c.stats['udp_socket_bindings'], 0)
            probe.side_effect = None
            self.assertTrue(self.c.evaluate(self.udp_event()))

    def test_xudp_handoff_invalidates_old_owner_without_a_new_access_record(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}), \
             mock.patch.object(g.time, 'time', side_effect=lambda: self.ts):
            stamp = dt.datetime.fromtimestamp(self.ts, g.UTC).strftime('%Y/%m/%d %H:%M:%S.%f')
            self.c.add_access(f'{stamp} [Info] [20001] common/mux: XUDP new [1 2 3 4 5 6 7 8]')
            self.access('198.51.100.10', 6881)
            self.udp_open()
            self.c.process_pending()
            self.ts += 10
            stamp = dt.datetime.fromtimestamp(self.ts, g.UTC).strftime('%Y/%m/%d %H:%M:%S.%f')
            self.c.add_access(f'{stamp} [Info] [9999] common/mux: XUDP hit [1 2 3 4 5 6 7 8]')
            self.assertFalse(self.c.evaluate(self.udp_event()))

    def test_stale_open_log_cannot_bind_a_current_socket_with_the_same_port(self):
        with mock.patch.object(g, 'read_udp_sockets', return_value={('::', 42000): {123}}):
            self.access('198.51.100.10', 6881)
            self.udp_open()
            with mock.patch.object(g.time, 'time', return_value=self.ts + 120):
                self.assertFalse(self.c.evaluate(self.udp_event()))

    def test_duplicate_pending_alerts_count_as_one_flow(self):
        payload=self.eve('198.51.100.1',31000,1)
        for _ in range(3):
            self.c.add_eve(payload)
        self.assertEqual(len(self.c.pending),1)
        self.access('198.51.100.1',31000)
        self.c.process_pending()
        self.c.add_eve(payload)
        self.assertFalse(self.c.pending)
        self.assertEqual(self.c.stats['matched'],1)
        self.assertEqual(self.fw.bans,[])

    def test_unmatched_alerts_expire_without_poisoning_seen_flows(self):
        self.cfg['correlation_buffer_seconds']=3
        with mock.patch.object(g.time,'monotonic',return_value=1000):
            self.c.add_eve(self.eve('198.51.100.1',31000,1))
        for tick in range(1004, 1010):
            with mock.patch.object(g.time,'monotonic',return_value=tick):
                self.c.process_pending()
        self.assertEqual(len(self.c.pending),1)
        self.assertEqual(self.c.stats['correlation_waits'],1)
        with mock.patch.object(g.time,'monotonic',return_value=1064), \
             self.assertLogs(g.LOG, 'WARNING') as log:
            self.c.process_pending()
        self.assertFalse(self.c.pending)
        self.assertFalse(self.c.pending_flows)
        self.assertFalse(self.c.seen_flows)
        self.assertEqual(self.c.stats['unmatched_expired'],1)
        self.assertEqual(self.c.stats['unmatched_no_access_for_peer'],1)
        self.assertIn('reason=no_access_for_peer',log.output[0])
        self.assertEqual(len(log.output),1)

    def test_expired_matches_report_separate_failure_reasons(self):
        for i, reason in enumerate(('time_window', 'client_ip_missing', 'multiple_client_ips')):
            peer, port = f'198.51.100.{i + 1}', 31000 + i
            if reason == 'time_window':
                self.ts -= 120
                self.access(peer, port)
                self.ts += 120
            elif reason == 'client_ip_missing':
                self.access(peer, port, client='unavailable')
            else:
                self.access(peer, port)
                self.access(peer, port, user='other', client='203.0.113.30')
            with mock.patch.object(g.time, 'monotonic', return_value=1000):
                self.c.add_eve(self.eve(peer, port, i))
            with mock.patch.object(g.time, 'monotonic', return_value=1061), \
                 self.assertLogs(g.LOG, 'WARNING') as log:
                self.c.process_pending()
            self.assertEqual(self.c.stats['unmatched_' + reason], 1)
            self.assertIn('reason=' + reason, log.output[0])
            if reason == 'time_window':
                self.assertIn('nearest_access_delta_seconds=121.0', log.output[0])
        self.assertEqual(self.c.stats['unmatched_expired'], 3)
        self.assertEqual(self.c.stats['matched'], 0)
        self.assertEqual(self.fw.bans, [])

    def test_failed_ban_retries_without_cooldown_or_new_flows(self):
        with mock.patch.object(self.fw,'ban',side_effect=[RuntimeError('temporary error'),[]]) as ban:
            with mock.patch.object(g.time,'monotonic',return_value=1000), \
                 self.assertLogs(g.LOG,level='ERROR'):
                for i in range(5):
                    self.event(f'198.51.100.{i+1}',31000+i,i)
            self.assertNotIn('203.0.113.20',self.c.cooldown)
            self.assertEqual(self.c.stats['bans'],0)
            with mock.patch.object(g.time,'monotonic',return_value=1004):
                self.c.process_pending()
            self.assertEqual(ban.call_count,1)
            with mock.patch.object(g.time,'monotonic',return_value=1005):
                self.c.process_pending()
            self.assertEqual(ban.call_count,2)
        self.assertEqual(self.c.stats['bans'],1)
        self.assertEqual(self.c.cooldown['203.0.113.20'],1605)
        self.assertFalse(self.c.retry_bans)
        records=[json.loads(line) for line in Path(self.cfg['audit_path']).read_text().splitlines()]
        self.assertTrue(records[0]['result'].startswith('ban-error:'))
        self.assertEqual(records[1]['result'],'banned-600s')

    def test_failed_ban_is_not_retried_with_expired_evidence(self):
        with mock.patch.object(self.fw,'ban',side_effect=RuntimeError('temporary error')) as ban:
            with mock.patch.object(g.time,'monotonic',return_value=1000), \
                 self.assertLogs(g.LOG,level='ERROR'):
                for i in range(5):
                    self.event(f'198.51.100.{i+1}',31000+i,i)
            with mock.patch.object(g.time,'monotonic',return_value=1005), \
                 mock.patch.object(g.time,'time',return_value=self.ts+10000):
                self.c.process_pending()
            self.assertEqual(ban.call_count,1)
        self.assertFalse(self.c.retry_bans)
        self.assertFalse(self.c.events)

    def test_audit_failure_does_not_crash_or_undo_ban_state(self):
        with mock.patch.object(g,'audit_append',side_effect=OSError('disk full')), \
             mock.patch.object(g.time,'monotonic',return_value=1000), \
             self.assertLogs(g.LOG,level='ERROR'):
            for i in range(5):
                self.event(f'198.51.100.{i+1}',31000+i,i)
        self.assertEqual(self.fw.bans,['203.0.113.20'])
        self.assertEqual(self.c.stats['bans'],1)
        self.assertEqual(self.c.cooldown['203.0.113.20'],1600)

    def test_fifth_distinct_flow_produces_ten_minute_ban(self):
        for i in range(4):
            self.event(f'198.51.100.{i+1}', 31000+i, i)
        self.assertEqual(self.fw.bans,[])
        with mock.patch.object(g.time,'monotonic',return_value=1000):
            self.event('198.51.100.5',31004,4)
        self.assertEqual(self.fw.bans,['203.0.113.20'])
        audit=json.loads(Path(self.cfg['audit_path']).read_text().strip())
        self.assertEqual(audit['result'],'banned-600s')
        self.assertEqual(audit['ban_seconds'],600)
        self.assertEqual(audit['client_ip'],'203.0.113.20')
        self.assertEqual(len(audit['evidence']),5)
        self.assertEqual(self.c.cooldown['203.0.113.20'],1600)
        self.assertFalse('panel' in audit)

    def test_five_flows_to_one_peer_do_not_trigger_ban(self):
        for i in range(5):
            self.event('198.51.100.1',31000+i,i)
        self.assertEqual(self.fw.bans,[])

    def test_cooldown_lasts_ten_minutes_and_reban_needs_new_evidence(self):
        base=self.ts
        with mock.patch.object(g.time,'monotonic',return_value=1000):
            for i in range(5):
                self.event(f'198.51.100.{i+1}',31000+i,i)
        self.ts=base+61
        with mock.patch.object(g.time,'monotonic',return_value=1061):
            for i in range(5):
                self.event(f'192.0.2.{i+1}',32000+i,i+10)
        self.assertEqual(len(self.fw.bans),1)
        self.ts=base+601
        with mock.patch.object(g.time,'monotonic',return_value=1601):
            for i in range(4):
                self.event(f'203.0.113.{i+1}',33000+i,i+20)
            self.assertEqual(len(self.fw.bans),1)
            self.event('203.0.113.5',33004,24)
        self.assertEqual(len(self.fw.bans),2)

    def test_old_flow_alerts_do_not_restart_ban_after_ten_minutes(self):
        with mock.patch.object(g.time,'monotonic',return_value=1000):
            for i in range(5):
                self.event(f'198.51.100.{i+1}',31000+i,i)
        self.ts+=601
        with mock.patch.object(g.time,'monotonic',return_value=1601):
            for i in range(5):
                self.event(f'198.51.100.{i+1}',31000+i,i)
        self.assertEqual(len(self.fw.bans),1)

    def test_repeat_requires_fresh_evidence(self):
        for i in range(5): self.event(f'198.51.100.{i+1}',31000+i,i)
        for i in range(5): self.event(f'192.0.2.{i+1}',32000+i,i+10)
        self.assertEqual(len(self.fw.bans),1)
        self.c.cooldown.clear()
        for i in range(5): self.event(f'203.0.113.{i+1}',33000+i,i+20)
        self.assertEqual(len(self.fw.bans),2)

    def test_shared_ip_is_banned(self):
        self.event('198.51.100.1',30001,1,user='other')
        for i in range(5): self.event(f'198.51.100.{i+1}',31000+i,i+100)
        self.assertEqual(self.fw.bans,['203.0.113.20'])
        audit=json.loads(Path(self.cfg['audit_path']).read_text().strip())
        self.assertEqual(audit['emails'],['client-a@example.test','other'])
        self.assertIsNone(audit['email'])

    def test_multiple_users_matching_one_ingress_ip_are_banned(self):
        for i in range(5):
            peer=f'198.51.100.{i+1}'
            self.access(peer,31000+i,user='other')
            self.event(peer,31000+i,i)
        self.assertEqual(self.fw.bans,['203.0.113.20'])

    def test_shared_ip_cannot_bypass_cooldown_with_another_user(self):
        for i in range(5): self.event(f'198.51.100.{i+1}',31000+i,i)
        for i in range(5): self.event(f'192.0.2.{i+1}',32000+i,i+10,user='other')
        self.assertEqual(self.fw.bans,['203.0.113.20'])

    def test_monitor_records_incident_without_banning(self):
        self.c.mode='monitor'
        for i in range(5): self.event(f'198.51.100.{i+1}',31000+i,i)
        self.assertEqual(self.fw.bans,[])
        audit=json.loads(Path(self.cfg['audit_path']).read_text().strip())
        self.assertEqual(audit['result'],'monitor-only')

    def test_peer_match_multiple_ips_not_banned(self):
        self.event('198.51.100.1',30001,1,client='203.0.113.20')
        self.event('198.51.100.1',30001,2,client='203.0.113.30')
        for i in range(3): self.event(f'198.51.100.{i+1}',31000+i,i+100)
        self.assertEqual(self.fw.bans,[])

    def test_ambiguous_peer_stays_ambiguous_after_120_connections(self):
        for i in range(5):
            peer=f'198.51.100.{i+1}'
            self.access(peer,31000+i,user='actual-offender',client='203.0.113.30')
            for _ in range(120):
                self.access(peer,31000+i,user='innocent')
            self.c.evaluate({'ts':self.ts+1,'proto':'UDP','peer':(peer,31000+i),
                             'flow':str(i),'sid':9100001})
        self.assertEqual(self.fw.bans,[])
        self.assertEqual(self.c.stats['correlation_waits'],5)

    def test_expired_evidence_is_removed_without_new_user_activity(self):
        self.event('198.51.100.1',30001,1)
        self.assertTrue(self.c.events)
        with mock.patch.object(g.time,'time',return_value=self.ts+10000):
            self.c.process_pending()
        self.assertFalse(self.c.events)
        self.assertFalse(self.c.access)
        self.assertFalse(self.c.seen_flows)

    def test_invalid_eve_objects_are_ignored(self):
        for payload in ('null','[]','{"event_type":"alert","alert":true}',
                        '{"event_type":"alert","alert":{"action":true}}'):
            with self.subTest(payload=payload):
                self.c.add_eve(payload)
        self.assertFalse(self.c.pending)

    def test_eve_diagnostics_distinguish_missing_events_from_rejected_alerts(self):
        cases = []
        event = json.loads(self.eve('198.51.100.1', 31000, 1))
        cases.append((dict(event, src_ip='10.20.30.40'), 'server_ip'))
        cases.append((dict(event, alert=dict(event['alert'], action='allowed')), 'not_blocked'))
        cases.append((dict(event, alert=dict(event['alert'], signature_id=123)), 'signature'))
        cases.append((dict(event, event_type='stats'), 'non_alert'))
        for payload, reason in cases:
            with self.subTest(reason=reason):
                self.c.add_eve(json.dumps(payload))
                self.assertEqual(self.c.stats['eve_ignored_' + reason], 1)
        self.c.add_eve('not-json')
        self.assertEqual(self.c.stats['eve_lines'], 5)
        self.assertEqual(self.c.stats['eve_invalid_json'], 1)
        self.assertEqual(self.c.stats['alerts'], 0)
        self.assertEqual(self.fw.bans, [])
        self.c.add_eve(json.dumps(event))
        self.access('198.51.100.1', 31000)
        self.c.process_pending()
        self.assertEqual(self.c.stats['eve_lines'], 6)
        self.assertEqual(self.c.stats['alerts'], 1)
        self.assertEqual(self.c.stats['matched'], 1)

    def test_stats_report_zero_eve_counts_when_only_access_is_received(self):
        self.c.add_access('an ordinary Xray diagnostic message')
        self.access('198.51.100.1', 31000)
        with mock.patch.object(g.time, 'monotonic', return_value=self.c.last_summary + 61), \
             self.assertLogs(g.LOG, 'INFO') as log:
            self.c.process_pending()
        self.assertEqual(self.c.stats['access_lines'], 2)
        self.assertEqual(self.c.stats['access'], 1)
        self.assertEqual(self.c.stats['access_ignored'], 1)
        self.assertIn("'eve_lines': 0", log.output[0])
        self.assertIn("'alerts': 0", log.output[0])

    def test_validate_rejects_configs_that_would_crash_at_startup(self):
        invalid=[
            ('access',{}),
            ('eve',{'type':'unsupported','path':'/tmp/eve.json'}),
            ('access',{'type':'file','path':None}),
            ('access',{'type':'docker','path':'/tmp/access.log','container':'-bad'}),
            ('signatures',[]),
            ('signatures',['not-a-number']),
            ('correlation_buffer_seconds','not-a-number'),
            ('correlation_buffer_seconds',float('nan')),
            ('correlation_buffer_seconds',float('inf')),
            ('correlation_buffer_seconds',-1),
            ('min_distinct_flows',1.5),
            ('min_distinct_peers',True),
            ('audit_path',''),
        ]
        for field,value in invalid:
            with self.subTest(field=field,value=value):
                cfg=copy.deepcopy(self.cfg)
                cfg[field]=value
                with self.assertRaises(ValueError):
                    g.validate(cfg)

    def test_guard_nonpublic_and_allowlist(self):
        firewall = g.Firewall(self.cfg['firewall'], self.srv)
        for ip in ('127.0.0.1', '10.0.0.1', '192.0.2.10', '198.51.100.3', '203.0.113.20'):
            self.assertFalse(firewall.allowed_to_ban(ip))
        # Public resolver addresses test the public/non-public policy without
        # embedding any real user's or server's address.
        self.assertTrue(firewall.allowed_to_ban('1.1.1.1'))
        firewall.allow = [g.ipaddress.ip_network('1.1.1.0/24')]
        self.assertFalse(firewall.allowed_to_ban('1.1.1.1'))

    def test_legacy_one_minute_config_requires_migration(self):
        cfg=copy.deepcopy(self.cfg)
        cfg['firewall']['ban_seconds']=60
        with self.assertRaisesRegex(ValueError,'ban_seconds=600'):
            g.validate(cfg)

    def test_nft_rules_block_all_ports_and_protocols(self):
        spec=self.fw.spec
        for family, name in (('ip', 'clients_v4'), ('ip6', 'clients_v6')):
            self.assertIn(f'{family} saddr @{name} counter drop',spec)
            self.assertIn(f'{family} daddr @{name} counter drop',spec)
        self.assertIn('timeout 600s',spec)
        self.assertNotIn('dport',spec)
        self.assertNotIn('sport',spec)
        self.assertNotIn(' tcp ',spec)
        self.assertNotIn(' udp ',spec)

    def test_existing_firewall_removes_port_limits_without_clearing_bans(self):
        cfg=copy.deepcopy(self.cfg['firewall'])
        cfg['tcp_ports']=[8443]
        cfg['udp_ports']=[8443]
        fw=g.Firewall(cfg,self.srv)
        legacy=self.fw.spec.replace('ip saddr @clients_v4 counter drop',
                                    'ip saddr @clients_v4 tcp dport 443 counter drop')
        existing=mock.Mock(returncode=0,stdout=legacy)
        with mock.patch.object(g.shutil,'which',return_value='/usr/sbin/nft'), \
             mock.patch.object(g,'run',return_value=existing) as fake:
            fw.ensure()
        self.assertTrue(fw.initialized)
        self.assertEqual(len(fake.call_args_list),3)
        checked,applied=fake.call_args_list[1:]
        self.assertEqual(checked.args[0],['nft','-c','-f','-'])
        self.assertEqual(applied.args[0],['nft','-f','-'])
        self.assertEqual(checked.kwargs['stdin'],applied.kwargs['stdin'])
        batch=applied.kwargs['stdin']
        for direction in ('input','output'):
            self.assertIn(f'flush chain inet {g.TABLE} {direction}',batch)
        self.assertIn('ip saddr @clients_v4 counter drop',batch)
        self.assertIn('ip6 daddr @clients_v6 counter drop',batch)
        self.assertNotIn('dport',batch)
        self.assertNotIn('sport',batch)
        self.assertNotIn('flush set',batch)
        self.assertNotIn('delete table',batch)
        self.assertNotIn('flush ruleset',batch)

    def test_firewall_update_is_not_applied_when_check_fails(self):
        existing=mock.Mock(returncode=0,stdout=self.fw.spec)
        fw=g.Firewall(self.cfg['firewall'],self.srv)
        with mock.patch.object(g.shutil,'which',return_value='/usr/sbin/nft'), \
             mock.patch.object(g,'run',side_effect=[existing,RuntimeError('invalid rules')]) as fake:
            with self.assertRaises(RuntimeError):
                fw.ensure()
        self.assertFalse(fw.initialized)
        self.assertEqual(len(fake.call_args_list),2)

    def test_firewall_recreates_deleted_table_before_retrying_ban(self):
        fw=g.Firewall(self.cfg['firewall'],self.srv)
        fw.initialized=True
        ok=mock.Mock(returncode=0,stdout='')
        missing=mock.Mock(returncode=1,stdout='')
        responses=[RuntimeError('table deleted'),missing,ok,ok,ok,ok]
        with mock.patch.object(fw,'allowed_to_ban',side_effect=lambda ip: ip == '203.0.113.20'), \
             mock.patch.object(g.shutil,'which',return_value='/usr/sbin/nft'), \
             mock.patch.object(g,'run',side_effect=responses) as fake:
            actions=fw.ban('203.0.113.20')
        calls=fake.call_args_list
        self.assertEqual(calls[0].args[0],calls[4].args[0])
        self.assertEqual(calls[1].args[0],['nft','list','table','inet',g.TABLE])
        self.assertEqual(calls[2].args[0],['nft','-c','-f','-'])
        self.assertEqual(calls[3].args[0],['nft','-f','-'])
        self.assertTrue(fw.initialized)
        self.assertTrue(actions[0]['ok'])

    def test_real_event_parser(self):
        e={'event_type':'alert','timestamp':dt.datetime.now(dt.timezone.utc).isoformat(),
            'alert':{'action':'blocked','signature_id':9100001},
            'src_ip':'192.0.2.10','src_port':50001,
            'dest_ip':'198.51.100.13','dest_port':32001,
            'proto':'UDP','flow_id':12345}
        x=g.get_peer_alert(e,self.srv,{9100001})
        self.assertEqual(x['peer'],('198.51.100.13',32001))

    def test_kill_all_tcp_connections_and_no_panel_api(self):
        calls=[]
        self.fw.initialized=True
        with mock.patch.object(g,'run') as fake:
            fake.return_value=mock.Mock(stdout='',returncode=0)
            result=g.Firewall.ban(self.fw,'203.0.113.20')
        self.assertEqual(len(result),1)
        args=[c.args[0] for c in fake.call_args_list]
        self.assertTrue(any(a[:3]==['nft','add','element'] for a in args))
        self.assertIn('{ 203.0.113.20 timeout 600s }',args[0])
        self.assertTrue(any(a[0]=='ss' and '-K' in a for a in args))
        ss_args=next(a for a in args if a[0]=='ss')
        self.assertNotIn('-4',ss_args)
        self.assertNotIn('-6',ss_args)
        self.assertEqual(ss_args[-1],'dst 203.0.113.20')
        self.assertNotIn('sport',ss_args[-1])
        self.assertTrue(all('GUARD_PANEL_TOKEN' not in str(a) for a in args))

    def test_ipv6_ban_uses_ipv6_set_and_unambiguous_socket_filter(self):
        self.fw.initialized=True
        ip='2001:db8:4::20'
        with mock.patch.object(g,'run') as fake:
            fake.return_value=mock.Mock(stdout='',returncode=0)
            result=g.Firewall.ban(self.fw,ip)
        args=[call.args[0] for call in fake.call_args_list]
        self.assertIn('clients_v6',args[0])
        ss_args=next(argv for argv in args if argv[0]=='ss')
        self.assertEqual(ss_args[-1],f'dst [{ip}]')
        self.assertTrue(result[0]['ok'])


class UdpTableTests(unittest.TestCase):
    @unittest.skipUnless(g.sys.byteorder == 'little', 'Linux x86 UDP table format')
    def test_real_kernel_table_formats_and_shared_port_inodes(self):
        ipv4 = ('sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
                '1: 140200C0:A410 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 123 2 0 0\n'
                '2: 140200C0:A410 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 456 2 0 0\n')
        ipv6 = ('sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
                '1: B80D0120000001000000000001000000:A410 00000000000000000000000000000000:0000 '
                '07 00000000:00000000 00:00000000 00000000 0 0 789 2 0 0\n')
        self.assertEqual(g.parse_udp_table(ipv4), {('192.0.2.20', 42000): {123, 456}})
        self.assertEqual(g.parse_udp_table(ipv6), {('2001:db8:1::1', 42000): {789}})
        with mock.patch.object(g.Path, 'read_text', side_effect=[ipv4, ipv6]):
            self.assertEqual(g.read_udp_sockets(), {
                ('192.0.2.20', 42000): {123, 456}, ('2001:db8:1::1', 42000): {789}})


class FollowerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'eve.json'
        self.path.write_text('historical\n',encoding='utf-8')
        self.out=queue.Queue(maxsize=2)
        self.f=g.FileFollower(self.path,'eve',self.out)
        self.addCleanup(self.f.close)
        self.f.step()

    def append(self,text):
        with self.path.open('a',encoding='utf-8') as file:
            file.write(text)

    def drain(self):
        lines=[]
        while not self.out.empty():
            lines.append(self.out.get_nowait()[1])
        return lines

    def test_full_queue_preserves_lines_for_next_step(self):
        self.append('first\nsecond\nthird\n')
        self.f.step()
        lines=self.drain()
        self.f.step()
        lines.extend(self.drain())
        self.assertEqual(lines,['first','second','third'])

    @unittest.skipIf(os.name=='nt','Rename of an open log is a Linux deployment scenario')
    def test_rotation_drains_old_file_before_reading_replacement(self):
        self.append('old1\nold2\nold3\nold4\nold5\n')
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_text('new1\n',encoding='utf-8')
        lines=[]
        for _ in range(10):
            self.f.step()
            lines.extend(self.drain())
        self.assertEqual(lines,['old1','old2','old3','old4','old5','new1'])

    def test_partial_line_is_completed_before_delivery(self):
        self.append('part')
        self.f.step()
        self.assertEqual(self.drain(),[])
        self.append('ial\n')
        self.f.step()
        self.assertEqual(self.drain(),['partial'])

    def test_truncation_reads_new_file_from_beginning(self):
        self.path.write_text('new\n',encoding='utf-8')
        self.f.step()
        self.assertEqual(self.drain(),['new'])


@unittest.skipIf(os.name == 'nt', 'Docker /proc roots require a Linux host')
class DockerFollowerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / 'access.log'
        self.log.write_text('historical\n', encoding='utf-8')
        self.out = queue.Queue(maxsize=2)
        self.follower = g.DockerFollower('marzban', '/var/log/access.log', 'access',
                                         self.out, proc=self.root / 'proc')
        self.addCleanup(self.follower.close)
        self.process(123)
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout='123\n')):
            self.follower.step()

    def process(self, pid):
        path = self.root / 'proc' / str(pid) / 'root/var/log/access.log'
        path.parent.mkdir(parents=True)
        path.hardlink_to(self.log)
        return path

    def append(self, text):
        with self.log.open('a', encoding='utf-8') as output:
            output.write(text)

    def drain(self):
        lines = []
        while not self.out.empty():
            lines.append(self.out.get_nowait()[1])
        return lines

    def test_restart_keeps_offset_and_reads_writes_during_disconnect(self):
        self.append('before\n')
        self.follower.step()
        self.assertEqual(self.drain(), ['before'])
        (self.root / 'proc/123').rename(self.root / 'exited')
        self.append('during\n')
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout='0\n')):
            self.follower.step()
        self.assertEqual(self.drain(), ['during'])
        self.process(456)
        self.append('after\n')
        self.follower.next_lookup = 0
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout='456\n')):
            self.follower.step()
        self.assertEqual(self.drain(), ['after'])

    def test_full_queue_preserves_docker_lines(self):
        self.append('first\nsecond\nthird\n')
        self.follower.step()
        lines = self.drain()
        self.follower.step()
        lines.extend(self.drain())
        self.assertEqual(lines, ['first', 'second', 'third'])

    def test_reused_pid_is_resolved_again_before_opening_another_root(self):
        (self.root / 'proc/123').rename(self.root / 'exited')
        self.process(123)
        self.follower.next_lookup = 0
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout='123\n')) as inspect:
            self.follower.step()
        inspect.assert_called_once()

    def test_unchanged_process_does_not_spawn_repeated_docker_commands(self):
        with mock.patch.object(g, 'run') as inspect:
            self.follower.step()
            self.follower.step()
        inspect.assert_not_called()

    def test_recreated_container_reads_its_new_log_from_the_beginning(self):
        self.append('last-old\n')
        (self.root / 'proc/123').rename(self.root / 'exited')
        replacement = self.process(456)
        replacement.unlink()
        replacement.write_text('first-new\n', encoding='utf-8')
        self.follower.next_lookup = 0
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout='456\n')):
            self.follower.step()
            lines = self.drain()
            self.follower.step()
            lines.extend(self.drain())
        self.assertEqual(lines, ['last-old', 'first-new'])

if __name__=='__main__':
    unittest.main(verbosity=2)

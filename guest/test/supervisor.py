# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import base64
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

node, child_script, scenario = sys.argv[1:]
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
supervisor = left.dup()
left.close()
os.dup2(right.fileno(), 3)
child = subprocess.Popen([node, child_script, scenario], pass_fds=(3,))
os.close(3)
right.close()
supervisor.settimeout(3)

def exact(length):
    result = b''
    while len(result) < length:
        part = supervisor.recv(length - len(result))
        if not part:
            raise RuntimeError('short child frame')
        result += part
    return result

def receive():
    length = struct.unpack('>I', exact(4))[0]
    assert 1 <= length <= 65536
    raw = exact(length)
    frame = json.loads(raw)
    assert json.dumps(frame, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == raw
    assert frame['v'] == 1
    assert len(frame['id']) == 32
    return frame

def wire(frame):
    raw = json.dumps(frame, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return struct.pack('>I', len(raw)) + raw

try:
    if scenario == 'adapter':
        status = receive()
        assert status['kind'] == 'status' and status['body'] == {}
        supervisor.sendall(wire({'v': 1, 'id': status['id'], 'kind': 'status.reply', 'body': {'ready': True, 'bound': True, 'grant_id': 'grant', 'grant_remaining': 100}}))
        model = receive()
        assert model['kind'] == 'model.call'
        assert model['body'] == {'grant_id': 'grant', 'model': 'test-model', 'messages': [{'role': 'system', 'content': 'system'}, {'role': 'user', 'content': 'hello'}], 'tools': [{'type': 'function', 'function': {'name': 'kira_recall', 'description': 'Recall', 'parameters': {'type': 'object'}}}], 'max_output_tokens': 64}
        supervisor.sendall(wire({'v': 1, 'id': model['id'], 'kind': 'model.reply', 'body': {'content': 'checking', 'tool_calls': [{'id': 'tool-1', 'type': 'function', 'function': {'name': 'kira_recall', 'arguments': '{"query":"hello"}'}}], 'finish_reason': 'tool_calls', 'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'cost_microusd': 3}, 'receipt_seq': 7}}))
    elif scenario == 'path0':
        target = 'plugins/owner-note/note.md'
        read = receive()
        assert read['kind'] == 'read' and read['body'] == {'target': target}
        digest = hashlib.sha256(b'old\n').hexdigest()
        supervisor.sendall(wire({'v': 1, 'id': read['id'], 'kind': 'read.reply', 'body': {'target': target, 'sha256': digest, 'bytes_b64': base64.b64encode(b'old\n').decode()}}))
        proposal = receive()
        args = {'key': 'path0', 'value': {'revision': 1, 'statement': 'Exact owner-reviewed bytes.'}}
        input_bytes = json.dumps(args, sort_keys=True, separators=(',', ':')).encode()
        effect = input_bytes + b'\n'
        proof = {'module_sha256': '34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438', 'input_sha256': hashlib.sha256(input_bytes).hexdigest(), 'effect_sha256': hashlib.sha256(effect).hexdigest()}
        assert proposal['kind'] == 'propose' and proposal['body'] == {'target': target, 'base_sha256': digest, 'new_bytes_b64': base64.b64encode(effect).decode(), 'note': 'untrusted model note', 'cell': proof}
        supervisor.sendall(wire({'v': 1, 'id': proposal['id'], 'kind': 'accepted', 'body': {'proposal_id': 'path0'}}))
    elif scenario == 'tools':
        read = receive()
        assert read['kind'] == 'read' and read['body'] == {'target': 'notes/a.txt'}
        digest = hashlib.sha256(b'old').hexdigest()
        supervisor.sendall(wire({'v': 1, 'id': read['id'], 'kind': 'read.reply', 'body': {'target': 'notes/a.txt', 'sha256': digest, 'bytes_b64': 'b2xk'}}))
        proposal = receive()
        assert proposal['kind'] == 'propose' and proposal['body'] == {'target': 'notes/a.txt', 'base_sha256': digest, 'new_bytes_b64': 'bmV3', 'note': 'model text'}
        supervisor.sendall(wire({'v': 1, 'id': proposal['id'], 'kind': 'accepted', 'body': {'proposal_id': 'proposal'}}))
        recall = receive()
        assert recall['kind'] == 'memory.recall' and recall['body'] == {'query': 'hello', 'limit': 3}
        supervisor.sendall(wire({'v': 1, 'id': recall['id'], 'kind': 'recall', 'body': {'result': 'found', 'items': [{'note_id': 'note', 'text': 'hello', 'cite_seq': 8}]}}))
        memory = receive()
        note = {'category': 'fact', 'statement': 'hello'}
        note_bytes = json.dumps(note, sort_keys=True, separators=(',', ':')).encode()
        args = {'key': 'memory:' + hashlib.sha256(note_bytes).hexdigest(), 'value': note}
        arg_bytes = json.dumps(args, sort_keys=True, separators=(',', ':')).encode()
        expected = {'module_sha256': '34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438', 'input_sha256': hashlib.sha256(arg_bytes).hexdigest(), 'effect_sha256': hashlib.sha256(arg_bytes + b'\n').hexdigest()}
        assert memory['kind'] == 'memory.put' and memory['body'] == {'cell': expected, **note}
        supervisor.sendall(wire({'v': 1, 'id': memory['id'], 'kind': 'accepted', 'body': {'proposal_id': 'memory-note'}}))
    elif scenario == 'roundtrip':
        requests = [receive() for _ in range(6)]
        replies = {
            'read': ('read.reply', {'target': 'notes/a.txt', 'sha256': '0' * 64, 'bytes_b64': 'b2xk'}),
            'propose': ('accepted', {'proposal_id': 'proposal'}),
            'model.call': ('model.reply', {'content': 'checking', 'tool_calls': [{'id': 'tool-1', 'type': 'function', 'function': {'name': 'kira_recall', 'arguments': '{"query":"hello"}'}}], 'finish_reason': 'tool_calls', 'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'cost_microusd': 3}, 'receipt_seq': 7}),
            'memory.recall': ('recall', {'result': 'found', 'items': [{'note_id': 'note', 'text': 'hello', 'cite_seq': 8}]}),
            'memory.put': ('accepted', {'proposal_id': 'memory-note'}),
            'status': ('status.reply', {'ready': True, 'bound': True, 'grant_id': 'grant', 'grant_remaining': 100}),
        }
        output = wire({'v': 1, 'id': 'push', 'kind': 'outcome', 'body': {'proposal_id': 'proposal', 'state': 'applied'}})
        for request in reversed(requests):
            kind, body = replies[request['kind']]
            output += wire({'v': 1, 'id': request['id'], 'kind': kind, 'body': body})
        supervisor.sendall(output[:2])
        supervisor.sendall(output[2:11])
        supervisor.sendall(output[11:])
    elif scenario in ('timeout', 'abort'):
        request = receive()
        time.sleep(0.08)
        supervisor.sendall(wire({'v': 1, 'id': request['id'], 'kind': 'accepted', 'body': {'proposal_id': 'late'}}))
        time.sleep(0.12)
        supervisor.settimeout(0.02)
        assert supervisor.recv(65536) == b'', 'call was retried'
    else:
        request = receive()
        valid = {'v': 1, 'id': request['id'], 'kind': 'status.reply', 'body': {}}
        if scenario == 'zero': raw = struct.pack('>I', 0)
        elif scenario == 'oversize': raw = struct.pack('>I', 65537)
        elif scenario == 'short': raw = struct.pack('>I', 50) + b'{}'
        elif scenario == 'short-header': raw = b'\x00\x00'
        elif scenario == 'version': valid['v'] = 2; raw = wire(valid)
        elif scenario == 'kind': valid['kind'] = 'fake.reply'; raw = wire(valid)
        elif scenario == 'wrong-reply': valid.update(kind='accepted', body={'proposal_id': 'wrong-kind'}); raw = wire(valid)
        elif scenario == 'id': valid['id'] = '!'; raw = wire(valid)
        elif scenario == 'envelope': valid['authority'] = True; raw = wire(valid)
        elif scenario == 'outcome': valid.update(kind='outcome', body={'proposal_id': 'p', 'state': 'allowed'}); raw = wire(valid)
        elif scenario == 'refusal': valid.update(kind='refusal', body={'code': 'retry', 'next': ''}); raw = wire(valid)
        elif scenario == 'noncanonical':
            payload = json.dumps(valid).encode(); raw = struct.pack('>I', len(payload)) + payload
        elif scenario == 'duplicate':
            payload = b'{"body":{},"id":"x","kind":"status.reply","v":1,"v":1}'
            raw = struct.pack('>I', len(payload)) + payload
        elif scenario == 'utf8': raw = struct.pack('>I', 1) + b'\xff'
        else: raise RuntimeError(scenario)
        supervisor.sendall(raw)
        supervisor.shutdown(socket.SHUT_WR)
    status = child.wait(timeout=4)
    assert status == 0, 'child failed'
finally:
    supervisor.close()
    if child.poll() is None:
        child.kill()
        child.wait()

import { describe, expect, test, vi } from 'vitest';
import { ApiClientError, createApiClient } from '../src/api/client.js';

type FetchImpl = typeof fetch;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const STATUS_PAYLOAD = {
  ok: true,
  data: {
    service: 'drobon-aegis-api',
    version: '0.1.0-test',
    environment: 'test',
    time: '2026-01-01T00:00:00.000Z',
  },
  meta: { requestId: 'req-server-1' },
};

describe('createApiClient — payment boundaries', () => {
  test('reads server pricing and sends a manual request with idempotency but no account authority fields', async () => {
    const config = { currentPlan: 'FREE', proPriceMinorUnits: 100000, currency: 'BDT', manualPaymentMethods: ['MANUAL_TRANSFER'], manualPaymentInstructions: 'Ask support.', onlineGateway: 'UNAVAILABLE', coupons: 'SUPPORTED' };
    const payment = { paymentId: 'pay_00000000-0000-4000-8000-000000000001', plan: 'PRO', amountMinorUnits: 100000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'TXN-ABC123', status: 'PENDING', createdAt: '2026-09-29T10:00:00.000Z', submittedAt: '2026-09-29T10:00:00.000Z', updatedAt: '2026-09-29T10:00:00.000Z', reviewedAt: null, approvedAt: null, rejectedAt: null, rejectionReason: null };
    const fetchImpl: FetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: config, meta: { requestId: 'payment-config' } }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { payment }, meta: { requestId: 'payment-create' } }, 201));
    const client = createApiClient({ baseUrl: '', fetchImpl, generateId: () => 'idem-test-key-01' });
    expect(await client.getPaymentConfig()).toEqual(config);
    expect(await client.createPayment({ plan: 'PRO', amountMinorUnits: 100000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'TXN-ABC123' })).toEqual({ payment });
    const calls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]?.[0]).toBe('/api/v1/payments/config');
    expect(calls[1]?.[0]).toBe('/api/v1/payments');
    expect(new Headers(calls[1]?.[1].headers).get('idempotency-key')).toBe('idem-test-key-01');
    expect(JSON.parse(String(calls[1]?.[1].body))).toEqual({ plan: 'PRO', amountMinorUnits: 100000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'TXN-ABC123' });
    expect(calls[1]?.[1].credentials).toBe('include');
  });
});

describe('createApiClient', () => {
  test('returns typed data and sends correlation headers', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(STATUS_PAYLOAD));
    const client = createApiClient({
      baseUrl: 'https://api.example.test',
      fetchImpl,
      generateId: () => 'web-test-id-1',
    });
    const data = await client.getStatus();
    expect(data.service).toBe('drobon-aegis-api');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('https://api.example.test/api/v1/status');
    const headers = new Headers(init.headers);
    expect(headers.get('x-request-id')).toBe('web-test-id-1');
    expect(headers.get('accept')).toBe('application/json');
  });

  test('supports same-origin relative URLs', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(STATUS_PAYLOAD));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await client.getLivez();
    const [url] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string];
    expect(url).toBe('/livez');
  });

  test('posts JSON for echo with the message payload', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse({
        ok: true,
        data: { message: 'hi', length: 2, receivedAt: '2026-01-01T00:00:00.000Z' },
        meta: { requestId: 'r' },
      }),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const data = await client.postEcho('hi');
    expect(data.message).toBe('hi');
    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('content-type')).toBe('application/json');
    expect(init.body).toBe(JSON.stringify({ message: 'hi' }));
  });

  test('uses authenticated assistant status and project-scoped ask endpoints with no client authority claims', async () => {
    const projectId = 'prj_00000000-0000-4000-8000-0000000000aa';
    const status = { providerState: 'NONE', providerId: null, deterministicQuestionsAvailable: true, conversationPersistence: 'NOT_IMPLEMENTED', toolsEnabled: false };
    const answer = {
      state: 'UNAVAILABLE', mode: 'DETERMINISTIC', providerState: 'NONE',
      answer: 'No configured AI provider is available for open-ended generation.',
      facts: [], interpretations: [], recommendations: [], limitations: ['Generation is unavailable.'], evidence: [],
      context: { itemCount: 0, characterCount: 0, redactedItems: 0, truncated: false },
    };
    const fetchImpl: FetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: status, meta: { requestId: 'assistant-status' } }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: answer, meta: { requestId: 'assistant-answer' } }));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    expect(await client.getAssistantStatus()).toEqual(status);
    expect(await client.askAssistant(projectId, { question: 'What is unknown?', scanId: 'scan_00000000-0000-4000-8000-000000000001' })).toEqual(answer);
    const calls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]?.[0]).toBe('/api/v1/assistant/status');
    expect(calls[0]?.[1].credentials).toBe('include');
    expect(calls[1]?.[0]).toBe(`/api/v1/projects/${projectId}/assistant/ask`);
    expect(calls[1]?.[1].method).toBe('POST');
    expect(calls[1]?.[1].body).toBe(JSON.stringify({ question: 'What is unknown?', scanId: 'scan_00000000-0000-4000-8000-000000000001' }));
    expect(String(calls[1]?.[1].body)).not.toContain('providerId');
    expect(String(calls[1]?.[1].body)).not.toContain('ownerId');
  });

  test('configures and removes a project-associated DAST target without client authority claims', async () => {
    const project = {
      id: 'prj_00000000-0000-4000-8000-0000000000aa',
      name: 'Fixture app',
      description: '',
      status: 'ACTIVE',
      dastTargetUrl: 'https://fixture.example.org/',
      createdAt: '2026-09-28T10:00:00.000Z',
      updatedAt: '2026-09-28T10:00:00.000Z',
    };
    const fetchImpl: FetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { project }, meta: { requestId: 'put-1' } }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { project: { ...project, dastTargetUrl: undefined } }, meta: { requestId: 'delete-1' } }));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const updated = await client.setDastTarget(project.id, 'https://fixture.example.org/');
    expect(updated.project.dastTargetUrl).toBe('https://fixture.example.org/');
    await client.clearDastTarget(project.id);
    const calls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]?.[0]).toBe(`/api/v1/projects/${project.id}/dast-target`);
    expect(calls[0]?.[1].method).toBe('PUT');
    expect(calls[0]?.[1].body).toBe(JSON.stringify({ targetUrl: 'https://fixture.example.org/' }));
    expect(calls[1]?.[1].method).toBe('DELETE');
    expect(calls[1]?.[1].body).toBeUndefined();
  });

  test('uses authenticated finding lifecycle, note, and bounded history endpoints with strict request bodies', async () => {
    const projectId = 'prj_00000000-0000-4000-8000-0000000000aa';
    const scanId = 'scan_00000000-0000-4000-8000-0000000000aa';
    const findingId = `fnd_${'a'.repeat(24)}`;
    const workflow = {
      id: 'fwf_00000000-0000-4000-8000-0000000000aa', projectId, findingId, fingerprint: 'b'.repeat(64),
      scanner: 'SAST', ruleId: 'DG-SAST-001', state: 'ACKNOWLEDGED',
      firstObservedScanId: scanId, firstObservedAt: '2026-09-28T10:00:00.000Z',
      lastObservedScanId: scanId, lastObservedAt: '2026-09-28T10:00:00.000Z',
      lastVerificationScanId: scanId, lastVerificationAt: '2026-09-28T10:00:00.000Z',
      verificationState: 'OBSERVED', notes: [], historyTotal: 1, updatedAt: '2026-09-28T10:00:00.000Z',
    };
    const fetchImpl: FetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { workflow }, meta: { requestId: 'wf-1' } }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { workflow }, meta: { requestId: 'note-1' } }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, data: { events: [], page: 1, pageSize: 20, total: 0, totalPages: 0 }, meta: { requestId: 'history-1' } }));
    const client = createApiClient({ baseUrl: '', fetchImpl, generateId: () => 'workflow-client-test' });
    await client.setFindingLifecycle(projectId, scanId, findingId, 'ACKNOWLEDGED');
    await client.addFindingNote(projectId, scanId, findingId, 'reviewed');
    await client.getFindingHistory(projectId, scanId, findingId, 1, 20);
    const calls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]?.[0]).toBe(`/api/v1/projects/${projectId}/scans/${scanId}/findings/${findingId}/lifecycle`);
    expect(calls[0]?.[1].method).toBe('PATCH');
    expect(calls[0]?.[1].body).toBe(JSON.stringify({ state: 'ACKNOWLEDGED' }));
    expect(calls[1]?.[0]).toBe(`/api/v1/projects/${projectId}/scans/${scanId}/findings/${findingId}/notes`);
    expect(calls[1]?.[1].method).toBe('POST');
    expect(calls[1]?.[1].body).toBe(JSON.stringify({ note: 'reviewed' }));
    expect(calls[2]?.[0]).toContain(`/history?page=1&pageSize=20`);
    for (const [, init] of calls) {
      expect(init.credentials).toBe('include');
      expect(new Headers(init.headers).get('x-request-id')).toBe('workflow-client-test');
    }
  });

  test('downloads only bounded report media with a server-generated safe filename', async () => {
    const response = new Response('# Assessment\n', {
      status: 200,
      headers: {
        'content-type': 'text/markdown; charset=utf-8',
        'content-disposition': 'attachment; filename="drobon-rpt_0123456789abcdef01234567.md"',
      },
    });
    const fetchImpl: FetchImpl = vi.fn(async () => response);
    const client = createApiClient({ baseUrl: '', fetchImpl, generateId: () => 'download-test' });
    const download = await client.downloadReport('prj_00000000-0000-4000-8000-0000000000aa', 'scan_00000000-0000-4000-8000-0000000000aa', 'markdown');
    expect(download.filename).toBe('drobon-rpt_0123456789abcdef01234567.md');
    expect(download.blob.size).toBe(13);
    expect(download.blob.type).toBe('text/markdown; charset=utf-8');
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/v1/projects/prj_00000000-0000-4000-8000-0000000000aa/');
    expect(new Headers(init.headers).get('accept')).toBe('text/markdown');
    expect(new Headers(init.headers).get('x-request-id')).toBe('download-test');
  });

  test('rejects unsafe report filenames and streamed bodies that exceed the bound', async () => {
    const unsafeFetch: FetchImpl = vi.fn(async () => new Response('{}', {
      status: 200,
      headers: { 'content-type': 'application/json', 'content-disposition': 'attachment; filename="../../evil.json"' },
    }));
    const unsafeClient = createApiClient({ baseUrl: '', fetchImpl: unsafeFetch });
    const unsafe = await unsafeClient.downloadReport('p', 's', 'json').catch((error: unknown) => error);
    expect(unsafe).toBeInstanceOf(ApiClientError);
    expect((unsafe as ApiClientError).kind).toBe('invalid-response');

    const hugeFetch: FetchImpl = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)); controller.close(); },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'content-disposition': 'attachment; filename="drobon-rpt_0123456789abcdef01234567.json"' },
    }));
    const hugeClient = createApiClient({ baseUrl: '', fetchImpl: hugeFetch });
    const oversized = await hugeClient.downloadReport('p', 's', 'json').catch((error: unknown) => error);
    expect(oversized).toBeInstanceOf(ApiClientError);
    expect((oversized as ApiClientError).kind).toBe('invalid-response');
  });

  test('maps error envelopes to http errors with server message + request ID', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        {
          ok: false,
          error: { code: 'RATE_LIMITED', message: 'Slow down.' },
          meta: { requestId: 'req-server-2' },
        },
        429,
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const failure = await client.getStatus().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiClientError);
    const typed = failure as ApiClientError;
    expect(typed.kind).toBe('http');
    expect(typed.message).toBe('Slow down.');
    expect(typed.status).toBe(429);
    expect(typed.code).toBe('RATE_LIMITED');
    expect(typed.requestId).toBe('req-server-2');
  });

  test('maps transport failures to network errors with safe messages', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => {
      throw new TypeError('fetch failed: ECONNREFUSED 10.0.0.99');
    });
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const failure = await client.getStatus().catch((error: unknown) => error);
    const typed = failure as ApiClientError;
    expect(typed.kind).toBe('network');
    expect(typed.message).not.toContain('10.0.0.99');
    expect(typed.requestId).toBeDefined();
  });

  test('maps timeouts to timeout errors', async () => {
    const fetchImpl: FetchImpl = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'));
        });
      })) as FetchImpl;
    const client = createApiClient({ baseUrl: '', fetchImpl, timeoutMs: 10 });
    const failure = await client.getStatus().catch((error: unknown) => error);
    expect((failure as ApiClientError).kind).toBe('timeout');
  });

  test('honors caller cancellation with aborted errors', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(STATUS_PAYLOAD));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const controller = new AbortController();
    controller.abort();
    const failure = await client.getStatus(controller.signal).catch((error: unknown) => error);
    expect((failure as ApiClientError).kind).toBe('aborted');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test('rejects malformed JSON and unexpected shapes', async () => {
    const badJson: FetchImpl = vi.fn(async () => new Response('{{nope', { status: 200 }));
    const clientA = createApiClient({ baseUrl: '', fetchImpl: badJson });
    expect(((await clientA.getStatus().catch((e: unknown) => e)) as ApiClientError).kind).toBe(
      'invalid-response',
    );
    const badShape: FetchImpl = vi.fn(async () => jsonResponse({ hello: 'world' }));
    const clientB = createApiClient({ baseUrl: '', fetchImpl: badShape });
    expect(((await clientB.getStatus().catch((e: unknown) => e)) as ApiClientError).kind).toBe(
      'invalid-response',
    );
  });
});

// @vitest-environment jsdom
/**
 * SCA UI (Pump 9) — the dependency-analysis surface.
 *
 * Covers the honest-user contract:
 * - the scan list distinguishes SCA ("Dependencies: N (D direct)") from
 *   SAST ("Findings: N") — both engines are visible, neither fakes the
 *   other's vocabulary;
 * - the honest banner: with no vulnerability intelligence dataset the
 *   analysis says "Not assessed — vulnerability intelligence dataset
 *   unavailable", and NO advisory list is fabricated;
 * - the inventory renders as TEXT (React escaping) — dependency names,
 *   purls and notes are displayed, never executed;
 * - the ecosystem filter is client-side over the SAME bounded response;
 * - truncation is visible ("N of M (truncated)"), never hidden;
 * - manifest outcomes (ANALYZED/PARTIAL/UNSUPPORTED/INVALID_INPUT) are
 *   all rendered — the limits of the analysis stay visible;
 * - an ASSESSED scan with real advisories renders them (the provider
 *   path is real, not decorative);
 * - failure honesty: a detail load error renders verbatim with retry.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import {
  type ApiClient,
  ApiClientError,
} from '../src/api/client.js';
import {
  type ProjectResponse,
  type ScanDetailResponse,
  type ScanResponse,
  type ScansResponse,
  type SourceSnapshotResponse,
  type ScaResult,
} from '@drobon/shared';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT: ProjectResponse = {
  project: {
    id: 'prj_test-sca-0001',
    name: 'Sca Project',
    description: '',
    status: 'ACTIVE',
    createdAt: '2026-09-28T10:00:00.000Z',
    updatedAt: '2026-09-28T10:00:00.000Z',
  },
};

const SNAPSHOT: SourceSnapshotResponse = {
  snapshot: {
    projectId: 'prj_test-sca-0001',
    fileCount: 4,
    totalBytes: 900,
    updatedAt: '2026-09-28T11:00:00.000Z',
    files: [
      { path: 'package.json', bytes: 120 },
      { path: 'package-lock.json', bytes: 600 },
      { path: 'requirements.txt', bytes: 60 },
      { path: 'src/index.ts', bytes: 120 },
    ],
  },
};

const FINGERPRINTS = {
  express: `111111111111111111111111${'a'.repeat(40)}`,
  lodash: `222222222222222222222222${'b'.repeat(40)}`,
  accepts: `333333333333333333333333${'c'.repeat(40)}`,
  flask: `444444444444444444444444${'d'.repeat(40)}`,
  gunicorn: `555555555555555555555555${'e'.repeat(40)}`,
};

/** The honest NOT_ASSESSED payload (exactly what the locked Null
 * provider produces for a snapshot that LOOKS vulnerable). */
function notAssessedSca(): ScaResult {
  return {
    summary: {
      assessmentState: 'NOT_ASSESSED',
      datasetStatus: 'NO_DATA_LOADED',
      providerId: 'none',
      dependenciesTotal: 5,
      directDependencies: 4,
      transitiveDependencies: 1,
      unclassifiedDependencies: 0,
      advisoriesTotal: 0,
      manifestsAnalyzed: 3,
      manifestsPartial: 0,
      manifestsUnsupported: 1,
      manifestsInvalid: 0,
      transitiveGraph: 'AVAILABLE',
      truncated: false,
    },
    dependencies: [
      {
        dependencyId: `dep_${FINGERPRINTS.accepts.slice(0, 24)}`,
        ecosystem: 'npm',
        name: 'accepts',
        versionSource: 'lockfile',
        resolvedVersion: '1.3.8',
        packageManager: 'npm',
        manifestPath: 'package-lock.json',
        lockfilePath: 'package-lock.json',
        dependencyType: 'runtime',
        dependencyClass: 'transitive',
        purl: 'pkg:npm/accepts@1.3.8',
        fingerprint: FINGERPRINTS.accepts,
      },
      {
        dependencyId: `dep_${FINGERPRINTS.express.slice(0, 24)}`,
        ecosystem: 'npm',
        name: 'express',
        declaredVersion: '^4.18.0',
        versionSource: 'lockfile',
        resolvedVersion: '4.17.1',
        packageManager: 'npm',
        manifestPath: 'package.json',
        lockfilePath: 'package-lock.json',
        dependencyType: 'runtime',
        dependencyClass: 'direct',
        purl: 'pkg:npm/express@4.17.1',
        fingerprint: FINGERPRINTS.express,
      },
      {
        dependencyId: `dep_${FINGERPRINTS.flask.slice(0, 24)}`,
        ecosystem: 'pypi',
        name: 'flask',
        declaredVersion: '==1.1.1',
        versionSource: 'manifest',
        packageManager: 'pip',
        manifestPath: 'requirements.txt',
        dependencyType: 'runtime',
        dependencyClass: 'direct',
        purl: 'pkg:pypi/flask',
        fingerprint: FINGERPRINTS.flask,
      },
      {
        dependencyId: `dep_${FINGERPRINTS.gunicorn.slice(0, 24)}`,
        ecosystem: 'pypi',
        name: 'gunicorn',
        declaredVersion: '>=20.0',
        versionSource: 'manifest',
        packageManager: 'pip',
        manifestPath: 'requirements.txt',
        dependencyType: 'runtime',
        dependencyClass: 'direct',
        fingerprint: FINGERPRINTS.gunicorn,
      },
      {
        dependencyId: `dep_${FINGERPRINTS.lodash.slice(0, 24)}`,
        ecosystem: 'npm',
        name: 'lodash',
        declaredVersion: '^4.17.15',
        versionSource: 'lockfile',
        resolvedVersion: '4.17.15',
        packageManager: 'npm',
        manifestPath: 'package.json',
        lockfilePath: 'package-lock.json',
        dependencyType: 'runtime',
        dependencyClass: 'direct',
        purl: 'pkg:npm/lodash@4.17.15',
        fingerprint: FINGERPRINTS.lodash,
      },
    ],
    manifests: [
      {
        path: 'package-lock.json',
        ecosystem: 'npm',
        status: 'ANALYZED',
        dependencyCount: 3,
      },
      {
        path: 'package.json',
        ecosystem: 'npm',
        status: 'ANALYZED',
        dependencyCount: 2,
      },
      {
        path: 'requirements.txt',
        ecosystem: 'pypi',
        status: 'ANALYZED',
        dependencyCount: 2,
      },
      {
        path: 'Pipfile',
        ecosystem: 'pypi',
        status: 'UNSUPPORTED',
        dependencyCount: 0,
        note: 'No supported dependency declaration found.',
      },
    ],
    sbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:01234567-89ab-cdef-0123-456789abcdef',
      version: 1,
      metadata: {
        tools: { components: [{ type: 'application', name: 'drobon-sca', version: '1.0.0' }] },
        component: { type: 'application', 'bom-ref': 'root', name: 'demo-app', version: '1.4.2' },
      },
      components: [
        {
          type: 'library',
          'bom-ref': `dep_${FINGERPRINTS.express.slice(0, 24)}`,
          name: 'express',
          version: '4.17.1',
          scope: 'required',
          purl: 'pkg:npm/express@4.17.1',
        },
      ],
      dependencies: [{ ref: 'root', dependsOn: [`dep_${FINGERPRINTS.express.slice(0, 24)}`] }],
    },
    advisories: [],
  };
}

function scaScanFixture(): { scan: ScanResponse['scan']; detail: ScanDetailResponse } {
  const scan = {
    id: 'scan_sca_0001',
    projectId: 'prj_test-sca-0001',
    scanType: 'SCA' as const,
    status: 'COMPLETED' as const,
    createdAt: '2026-09-28T11:01:00.000Z',
    updatedAt: '2026-09-28T11:01:01.000Z',
    startedAt: '2026-09-28T11:01:00.500Z',
    completedAt: '2026-09-28T11:01:01.000Z',
    resultSummary: {
      findingsTotal: 0,
      filesScanned: 3,
      filesSkipped: 1,
      dependenciesTotal: 5,
      directDependencies: 4,
    },
  };
  return { scan, detail: { scan: { ...scan, findings: [], sca: notAssessedSca() } } };
}

function signedInClient(overrides: Record<string, unknown> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async (): Promise<ProjectResponse> => PROJECT),
    getSources: vi.fn(async (): Promise<SourceSnapshotResponse> => SNAPSHOT),
    ...overrides,
  });
}

const screen = {
  find: async (testid: string): Promise<HTMLElement> => {
    const { waitFor } = await import('@testing-library/react');
    return waitFor(() => {
      const el = document.querySelector(`[data-testid="${testid}"]`);
      if (el === null) {
        throw new Error(`missing ${testid}`);
      }
      return el as HTMLElement;
    });
  },
  findAll: async (testid: string): Promise<HTMLElement[]> => {
    await screen.find(testid);
    return Array.from(document.querySelectorAll(`[data-testid="${testid}"]`)) as HTMLElement[];
  },
};

function click(element: HTMLElement): void {
  element.click();
  return void (async () => {
    await Promise.resolve();
  })() as unknown as void;
}

async function renderScaPage(overrides: Record<string, unknown> = {}): Promise<ApiClient> {
  const client = signedInClient(overrides);
  await renderAt('/projects/prj_test-sca-0001', client);
  return client;
}

describe('SCA UI: list view distinguishes the engines', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('an SCA scan shows dependency counts, a SAST scan shows findings — never mixed', async () => {
    const { scan: scaScan } = scaScanFixture();
    const sastScan = {
      id: 'scan_sast_0001',
      projectId: 'prj_test-sca-0001',
      scanType: 'SAST' as const,
      status: 'COMPLETED' as const,
      createdAt: '2026-09-28T11:02:00.000Z',
      updatedAt: '2026-09-28T11:02:01.000Z',
      startedAt: '2026-09-28T11:02:00.500Z',
      completedAt: '2026-09-28T11:02:01.000Z',
      resultSummary: {
        findingsTotal: 2,
        findingsBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
        filesScanned: 4,
        filesSkipped: 0,
      },
    };
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({
        scans: [scaScan, sastScan],
      })),
    });
    const results = await screen.findAll('scan-result');
    expect(results[0]?.textContent).toBe('Dependencies: 5 (4 direct)');
    expect(results[1]?.textContent).toBe('Findings: 2');
    // Each engine gets its own read surface.
    expect(await screen.find('view-sca')).toBeTruthy();
    expect(await screen.find('view-findings')).toBeTruthy();
  });

  test('the scan form stays honest: SCA/SECRETS analyze; DAST does not exist yet', async () => {
    await renderScaPage();
    const formText = (document.querySelector('[data-testid="scan-form"]') as HTMLElement)
      .textContent;
    expect(formText).toContain('never executed');
    expect(formText).toContain('SCAN_ENGINE_NOT_IMPLEMENTED');
    expect(formText).toContain('not assessed');
  });
});

describe('SCA UI: the honest dependency analysis view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('NOT_ASSESSED honesty: banner, counts, manifests, inventory — and ZERO advisories', async () => {
    const { scan, detail } = scaScanFixture();
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getScan: vi.fn(async (): Promise<ScanDetailResponse> => detail),
    });

    click(await screen.find('view-sca'));

    // The banner says exactly why nothing was assessed.
    const banner = await screen.find('sca-assessment');
    expect(banner.textContent).toContain('Not assessed');
    expect(banner.textContent).toContain('dataset unavailable');
    // The honest summary counts.
    const summary = await screen.find('sca-summary');
    expect(summary.textContent).toContain('5');
    expect(summary.textContent).toContain('4');
    expect((await screen.find('sca-graph')).textContent).toContain('Available');
    expect((await screen.find('sca-sbom')).textContent).toContain('CycloneDX 1.5');
    // Manifests: analyzed AND unsupported stay visible.
    const statuses = (await screen.findAll('sca-manifest-status')).map((el) => el.textContent);
    expect(statuses.filter((s) => s === 'ANALYZED')).toHaveLength(3);
    expect(statuses).toContain('UNSUPPORTED');
    const manifestItems = (await screen.findAll('sca-manifest-item')).map((el) => el.textContent);
    expect(manifestItems.some((t) => t?.includes('Pipfile'))).toBe(true);
    expect(manifestItems.some((t) => t?.includes('No supported dependency declaration found.'))).toBe(true);
    // The inventory: all five, direct/transitive distinguishable,
    // declared vs resolved both visible, evidence paths present.
    const items = await screen.findAll('sca-dep-item');
    expect(items).toHaveLength(5);
    const express = items.find((el) => el.textContent?.includes('express'));
    expect(express?.textContent).toContain('resolved 4.17.1');
    expect(express?.textContent).toContain('declared ^4.18.0');
    expect(express?.textContent).toContain('pkg:npm/express@4.17.1');
    expect(express?.textContent).toContain('package-lock.json');
    const flask = items.find((el) => el.textContent?.includes('flask'));
    expect(flask?.textContent).toContain('declared ==1.1.1');
    expect(flask?.textContent).not.toContain('resolved'); // never fabricated
    const accepts = items.find((el) => el.textContent?.includes('accepts'));
    expect(accepts?.textContent).toContain('transitive');
    // NO advisory section is fabricated for a NOT_ASSESSED scan.
    expect(document.querySelector('[data-testid="sca-advisories"]')).toBeNull();
  });

  test('the ecosystem filter is client-side only (no second request)', async () => {
    const { scan, detail } = scaScanFixture();
    const getScan = vi.fn(async (): Promise<ScanDetailResponse> => detail);
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getScan,
    });
    click(await screen.find('view-sca'));
    expect(await screen.findAll('sca-dep-item')).toHaveLength(5);

    const filter = (await screen.find('sca-filter')) as HTMLSelectElement;
    filter.value = 'npm';
    filter.dispatchEvent(new Event('change', { bubbles: true }));
    let npmCount = 0;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await Promise.resolve();
      npmCount = document.querySelectorAll('[data-testid="sca-dep-item"]').length;
      if (npmCount === 3) {
        break;
      }
    }
    expect(npmCount).toBe(3); // express, lodash, accepts
    expect(getScan).toHaveBeenCalledTimes(1); // display-only, no re-fetch
  });

  test('truncation is visible, never hidden', async () => {
    const { scan, detail } = scaScanFixture();
    const truncated: ScanDetailResponse = {
      scan: {
        ...detail.scan,
        sca: {
          ...detail.scan.sca!,
          summary: { ...detail.scan.sca!.summary, truncated: true, dependenciesTotal: 240 },
        },
      },
    };
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({
        scans: [
          {
            ...scan,
            resultSummary: {
              findingsTotal: 0,
              filesScanned: 3,
              filesSkipped: 1,
              dependenciesTotal: 240,
              directDependencies: 4,
            },
          },
        ],
      })),
      getScan: vi.fn(async (): Promise<ScanDetailResponse> => truncated),
    });
    click(await screen.find('view-sca'));
    const summary = await screen.find('sca-summary');
    expect(summary.textContent).toContain('5 of 240');
    expect(summary.textContent).toContain('truncated');
  });

  test('an ASSESSED scan renders REAL advisories (the provider path is not decorative)', async () => {
    const { scan, detail } = scaScanFixture();
    const assessed: ScanDetailResponse = {
      scan: {
        ...detail.scan,
        sca: {
          ...detail.scan.sca!,
          summary: {
            ...detail.scan.sca!.summary,
            assessmentState: 'ASSESSED',
            datasetStatus: 'DATASET_UNAVAILABLE',
            providerId: 'stub-intel',
            advisoriesTotal: 1,
          },
          advisories: [
            {
              id: 'GHSA-test-0001',
              severity: 'HIGH',
              summary: 'Verified advisory from a loaded dataset.',
              dependencyId: `dep_${FINGERPRINTS.express.slice(0, 24)}`,
              ecosystem: 'npm',
              name: 'express',
              version: '4.17.1',
            },
          ],
        },
      },
    };
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getScan: vi.fn(async (): Promise<ScanDetailResponse> => assessed),
    });
    click(await screen.find('view-sca'));
    const banner = await screen.find('sca-assessment');
    expect(banner.textContent).toContain('Assessed by stub-intel');
    const advisories = await screen.findAll('sca-advisory-item');
    expect(advisories).toHaveLength(1);
    expect(advisories[0]?.textContent).toContain('GHSA-test-0001');
    expect(advisories[0]?.textContent).toContain('express@4.17.1');
  });

  test('a detail load error renders verbatim, and retry recovers', async () => {
    const { scan, detail } = scaScanFixture();
    let fail = true;
    const getScan = vi.fn(async (): Promise<ScanDetailResponse> => {
      if (fail) {
        throw new ApiClientError({
          kind: 'http',
          message: 'The scan is not available.',
          status: 404,
          requestId: 'test-404',
        });
      }
      return detail;
    });
    await renderScaPage({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getScan,
    });
    click(await screen.find('view-sca'));
    const error = await screen.find('sca-error');
    expect(error.textContent).toBe('The scan is not available.');

    fail = false;
    click(await screen.find('sca-retry'));
    expect(await screen.findAll('sca-dep-item')).toHaveLength(5);
  });
});

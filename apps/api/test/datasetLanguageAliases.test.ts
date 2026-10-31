import { describe, expect, test } from 'vitest';
import { SAST_LANGUAGE_CATALOG, detectLanguageFamily, isAnalyzedMaturity } from '../src/scans/sast/languages.js';
import { CONFIG_FAMILY, resolvePackLanguages, unresolvedPackLanguageIds } from '../src/external/languageAliases.js';

const catalogIds = new Set(SAST_LANGUAGE_CATALOG.map((family) => family.id));

describe('dataset pack language reachability (GAP-040)', () => {
  test('the catalog contains the shared config family and keeps FULL at zero', () => {
    expect(catalogIds.has(CONFIG_FAMILY)).toBe(true);
    expect(SAST_LANGUAGE_CATALOG.some((f) => f.maturity === 'FULL')).toBe(false);
  });

  test('config files are detected by exact filename or extension', () => {
    expect(detectLanguageFamily('etc/nginx.conf')?.family).toBe(CONFIG_FAMILY);
    expect(detectLanguageFamily('etc/sshd_config')?.family).toBe(CONFIG_FAMILY); // exact filename, no extension
    expect(detectLanguageFamily('config/settings.ini')?.family).toBe(CONFIG_FAMILY);
    expect(detectLanguageFamily('build.gradle')?.family).toBe(CONFIG_FAMILY);
    expect(detectLanguageFamily('Dockerfile')?.family).toBe('dockerfile');
  });

  test('template rules reach normal template filenames without losing PHP rules for Blade', () => {
    for (const path of ['view.ejs', 'view.hbs', 'view.jsp', 'view.pug', 'view.tpl', 'view.twig', 'view.jinja', 'view.j2']) {
      expect(detectLanguageFamily(path)?.family, path).toBe(CONFIG_FAMILY);
    }
    expect(detectLanguageFamily('views/home.blade.php')?.family).toBe('php');
    expect(resolvePackLanguages(['blade'], catalogIds)).toEqual(['php']);
  });

  test('declared aliases restore the two ids the dataset flagged', () => {
    expect(resolvePackLanguages(['shell', 'gha'], catalogIds)).toEqual(['shell-posix', 'github-actions']);
    expect(resolvePackLanguages(['k8s', 'compose', 'istio'], catalogIds)).toEqual(['yaml']);
    expect(resolvePackLanguages(['nginx', 'redis', 'vault'], catalogIds)).toEqual([CONFIG_FAMILY]);
  });

  test('universal rules stay universal; unknown ids are reported, never guessed', () => {
    expect(resolvePackLanguages(undefined, catalogIds)).toBeUndefined();
    expect(unresolvedPackLanguageIds(['javascript', 'shell', 'made-up-id'], catalogIds)).toEqual(['made-up-id']);
    expect(resolvePackLanguages(['javascript', 'made-up-id'], catalogIds)).toEqual(['javascript']);
    expect(isAnalyzedMaturity('CONFIG_ANALYSIS')).toBe(true);
  });
});

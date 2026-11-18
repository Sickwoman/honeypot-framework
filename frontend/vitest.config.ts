import { defineConfig } from 'vitest/config';

// Node 25+ ships its own global `localStorage` (Web Storage, on by default).
// It shadows the one jsdom provides, so in the test environment `localStorage`
// comes back undefined and every app test fails before it starts. Turning
// Node's implementation off in the test workers lets jsdom's take over again.
// Harmless on Node 22/24 (what CI runs), where the flag already defaults off.
export default defineConfig({
  test: {
    pool: 'forks',
    poolOptions: {
      forks: {
        execArgv: ['--no-experimental-webstorage'],
      },
    },
  },
});

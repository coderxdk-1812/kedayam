import { mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const zipPath = 'public/kedayam.zip';
mkdirSync('public', { recursive: true });

for (const cmd of [
  ['bun', ['scripts/generate-icons.mjs']],
  ['bun', ['scripts/validate-extension.mjs', 'extension']],
]) {
  const result = spawnSync(cmd[0], cmd[1], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

rmSync(zipPath, { force: true });
const zipper = spawnSync('bash', ['-lc', `nix run nixpkgs#zip -- -qr /dev-server/${zipPath} . -x "*.DS_Store"`], {
  cwd: 'extension',
  stdio: 'inherit',
});
if (zipper.status !== 0) process.exit(zipper.status ?? 1);
console.log(`Packaged ${zipPath}`);

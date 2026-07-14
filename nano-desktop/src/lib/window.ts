import { LogicalSize, getCurrentWindow } from '@tauri-apps/api/window';

/**
 * The auth flow wants a small centered panel; the app wants a workspace. Resize
 * the real window rather than letting a 520px form float in a 1540px void.
 *
 * Silently no-ops outside Tauri (plain `vite dev` in a browser).
 */
const CHROME = {
  auth: { size: new LogicalSize(1040, 660), min: new LogicalSize(1040, 660) },
  app: { size: new LogicalSize(1540, 930), min: new LogicalSize(1100, 680) },
} as const;

export async function setWindowChrome(mode: keyof typeof CHROME): Promise<void> {
  try {
    const window = getCurrentWindow();
    const { size, min } = CHROME[mode];
    // Min first when growing, last when shrinking — a min larger than the
    // target size would clamp the resize.
    if (mode === 'app') {
      await window.setMinSize(min);
      await window.setSize(size);
    } else {
      await window.setMinSize(CHROME.auth.min);
      await window.setSize(size);
      await window.setMinSize(min);
    }
    await window.center();
  } catch {
    // Not running under Tauri.
  }
}

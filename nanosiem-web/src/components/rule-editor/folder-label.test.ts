// NAN-5581: reserved folder ids render with their label; the stored value is unchanged.
import { describe, expect, it } from 'vitest';
import { folderLabel } from './helpers';

describe('folderLabel', () => {
  it('labels the agent detections folder', () => {
    expect(folderLabel('agent_detections')).toBe('Agent detections');
  });
  it('leaves every other folder as is', () => {
    expect(folderLabel('identity')).toBe('identity');
    expect(folderLabel('My_Folder')).toBe('My_Folder');
  });
});

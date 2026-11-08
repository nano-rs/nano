import { describe, expect, it } from 'vitest';
import { stripComments } from './utils';

// NAN-4902: the client strips comments before sending, so it must agree with
// the server's nPL strip_comments — `//` and `/*` open a comment only at the
// start of the query or after whitespace (outside quotes).
describe('stripComments', () => {
  it('keeps bare URLs intact', () => {
    expect(stripComments('http://evil.example/payload | stats count')).toBe(
      'http://evil.example/payload | stats count',
    );
    expect(stripComments('url=https://x/y/z')).toBe('url=https://x/y/z');
  });

  it('keeps URL path globs and regex literals', () => {
    expect(stripComments('uri=/api/* | head 5')).toBe('uri=/api/* | head 5');
    expect(stripComments('path=/a\\// | head 1')).toBe('path=/a\\// | head 1');
    expect(stripComments('user = /admin.*/ | head 1')).toBe('user = /admin.*/ | head 1');
  });

  it('never strips inside single or double quotes', () => {
    expect(stripComments('url="http://a //b" x')).toBe('url="http://a //b" x');
    expect(stripComments("url='a // b /* c */' x")).toBe("url='a // b /* c */' x");
  });

  it('a trailing backslash does not escape the closing quote (NAN-1157)', () => {
    expect(stripComments('path="C:\\Windows\\" // note')).toBe('path="C:\\Windows\\"');
  });

  it('strips own-line, trailing, leading and block comments', () => {
    expect(stripComments('base\n// note\n| where x=1')).toBe('base\n \n| where x=1');
    expect(stripComments('error // trailing')).toBe('error');
    expect(stripComments('// leading\nerror')).toBe('error');
    expect(stripComments('error /* block\nspanning */ | head 1')).toBe('error   | head 1');
    expect(stripComments('/* only */')).toBe('');
  });

  it('an unterminated block comment swallows the rest', () => {
    expect(stripComments('error /* open')).toBe('error');
  });
});

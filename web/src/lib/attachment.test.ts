import { describe, it, expect } from 'vitest';
import {
  isAttachmentField,
  isAttachmentMetaField,
  attachmentFilename,
  attachmentFieldName,
  attachmentMetaFieldName,
  sanitizeFilename,
  formatFileSize,
  itemAttachments,
  ATTACHMENT_PREFIX,
  ATTACHMENT_META_PREFIX,
  MAX_FILENAME_LENGTH,
} from '@/types/vault';
import type { VaultItem } from '@/types/vault';

describe('isAttachmentField', () => {
  it('returns true for attachment content fields', () => {
    expect(isAttachmentField('_att.test.pdf')).toBe(true);
    expect(isAttachmentField('_att.id_rsa')).toBe(true);
    expect(isAttachmentField('_att.a')).toBe(true);
  });

  it('returns false for non-attachment fields', () => {
    expect(isAttachmentField('_attmeta.test.pdf')).toBe(false);
    expect(isAttachmentField('password')).toBe(false);
    expect(isAttachmentField('_name')).toBe(false);
    expect(isAttachmentField('_att')).toBe(false);
    expect(isAttachmentField('')).toBe(false);
  });
});

describe('isAttachmentMetaField', () => {
  it('returns true for attachment meta fields', () => {
    expect(isAttachmentMetaField('_attmeta.test.pdf')).toBe(true);
    expect(isAttachmentMetaField('_attmeta.id_rsa')).toBe(true);
  });

  it('returns false for non-meta fields', () => {
    expect(isAttachmentMetaField('_att.test.pdf')).toBe(false);
    expect(isAttachmentMetaField('password')).toBe(false);
    expect(isAttachmentMetaField('_attmeta')).toBe(false);
    expect(isAttachmentMetaField('')).toBe(false);
  });
});

describe('attachmentFilename', () => {
  it('extracts filename from _att. prefix', () => {
    expect(attachmentFilename('_att.my-key.pem')).toBe('my-key.pem');
    expect(attachmentFilename('_att.doc')).toBe('doc');
  });

  it('extracts filename from _attmeta. prefix', () => {
    expect(attachmentFilename('_attmeta.my-key.pem')).toBe('my-key.pem');
  });

  it('returns empty string for non-attachment fields', () => {
    expect(attachmentFilename('password')).toBe('');
    expect(attachmentFilename('')).toBe('');
  });
});

describe('attachmentFieldName / attachmentMetaFieldName', () => {
  it('builds correct field names', () => {
    expect(attachmentFieldName('doc.pdf')).toBe('_att.doc.pdf');
    expect(attachmentMetaFieldName('doc.pdf')).toBe('_attmeta.doc.pdf');
  });

  it('uses the correct prefixes', () => {
    expect(attachmentFieldName('f').startsWith(ATTACHMENT_PREFIX)).toBe(true);
    expect(attachmentMetaFieldName('f').startsWith(ATTACHMENT_META_PREFIX)).toBe(true);
  });
});

describe('sanitizeFilename', () => {
  it('passes through normal filenames', () => {
    expect(sanitizeFilename('normal.pdf')).toBe('normal.pdf');
    expect(sanitizeFilename('my-key.pem')).toBe('my-key.pem');
    expect(sanitizeFilename('id_rsa')).toBe('id_rsa');
  });

  it('strips path components', () => {
    expect(sanitizeFilename('/etc/passwd')).toBe('passwd');
    expect(sanitizeFilename('C:\\Users\\file.txt')).toBe('file.txt');
    expect(sanitizeFilename('a/b/c/d.txt')).toBe('d.txt');
  });

  it('replaces double dots', () => {
    expect(sanitizeFilename('..secrets')).toBe('_secrets');
    expect(sanitizeFilename('a..b')).toBe('a_b');
  });

  it('replaces colons', () => {
    expect(sanitizeFilename('file:name')).toBe('file_name');
  });

  it('truncates to max length', () => {
    const long = 'a'.repeat(200) + '.pdf';
    const result = sanitizeFilename(long);
    expect(result.length).toBeLessThanOrEqual(MAX_FILENAME_LENGTH);
  });

  it('returns "unnamed" for empty result', () => {
    expect(sanitizeFilename('')).toBe('unnamed');
  });
});

describe('formatFileSize', () => {
  it('formats bytes', () => {
    expect(formatFileSize(0)).toBe('0 B');
    expect(formatFileSize(500)).toBe('500 B');
    expect(formatFileSize(1023)).toBe('1023 B');
  });

  it('formats kilobytes', () => {
    expect(formatFileSize(1024)).toBe('1.0 KB');
    expect(formatFileSize(1536)).toBe('1.5 KB');
    expect(formatFileSize(10240)).toBe('10.0 KB');
  });

  it('formats megabytes', () => {
    expect(formatFileSize(1048576)).toBe('1.0 MB');
    expect(formatFileSize(1572864)).toBe('1.5 MB');
  });
});

describe('itemAttachments', () => {
  const makeItem = (fields: Record<string, string>): VaultItem => ({
    id: 'test-item',
    fields,
  });

  it('extracts attachments from item fields', () => {
    const item = makeItem({
      _name: 'Test',
      _type: 'custom',
      '_att.doc.pdf': 'base64data',
      '_attmeta.doc.pdf': '{"content_type":"application/pdf","size":1234}',
      password: 'secret',
    });
    const atts = itemAttachments(item);
    expect(atts).toHaveLength(1);
    expect(atts[0].filename).toBe('doc.pdf');
    expect(atts[0].meta.content_type).toBe('application/pdf');
    expect(atts[0].meta.size).toBe(1234);
    expect(atts[0].dataFieldName).toBe('_att.doc.pdf');
  });

  it('extracts multiple attachments', () => {
    const item = makeItem({
      '_att.a.txt': 'data1',
      '_attmeta.a.txt': '{"content_type":"text/plain","size":10}',
      '_att.b.png': 'data2',
      '_attmeta.b.png': '{"content_type":"image/png","size":2000}',
    });
    const atts = itemAttachments(item);
    expect(atts).toHaveLength(2);
    const filenames = atts.map((a) => a.filename).sort();
    expect(filenames).toEqual(['a.txt', 'b.png']);
  });

  it('skips malformed metadata', () => {
    const item = makeItem({
      '_att.doc.pdf': 'data',
      '_attmeta.doc.pdf': 'not-valid-json',
    });
    const atts = itemAttachments(item);
    expect(atts).toHaveLength(0);
  });

  it('returns empty for items with no attachments', () => {
    const item = makeItem({
      _name: 'Login',
      username: 'admin',
      password: 'secret',
    });
    expect(itemAttachments(item)).toHaveLength(0);
  });

  it('returns empty for empty fields', () => {
    const item = makeItem({});
    expect(itemAttachments(item)).toHaveLength(0);
  });
});

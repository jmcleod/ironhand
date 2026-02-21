export type ItemType = 'login' | 'note' | 'card' | 'certificate' | 'custom';

export interface VaultItem {
  id: string;
  fields: Record<string, string>;
}

export interface MemberInfo {
  member_id: string;
  role: string;
  status: string;
  added_epoch: number;
}

export interface Vault {
  id: string;
  name: string;
  description: string;
  items: VaultItem[];
  members: MemberInfo[];
  createdAt: string;
  updatedAt: string;
  epoch: number;
  itemCount: number;
  isCA?: boolean;
}

// Conventional metadata field names (prefixed with _)
export const FIELD_NAME = '_name';
export const FIELD_TYPE = '_type';
export const FIELD_CREATED = '_created';
export const FIELD_UPDATED = '_updated';

export function itemName(item: VaultItem): string {
  return item.fields[FIELD_NAME] || item.id;
}

export function itemType(item: VaultItem): ItemType {
  return (item.fields[FIELD_TYPE] as ItemType) || 'custom';
}

export function itemCreatedAt(item: VaultItem): string {
  return item.fields[FIELD_CREATED] || '';
}

export function itemUpdatedAt(item: VaultItem): string {
  return item.fields[FIELD_UPDATED] || '';
}

// Returns only the user-facing fields (excludes _ prefixed metadata)
export function userFields(item: VaultItem): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(item.fields)) {
    if (!k.startsWith('_')) {
      result[k] = v;
    }
  }
  return result;
}

// Field names that should be masked by default
export const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'card_number', 'totp', 'private_key']);

// ---------------------------------------------------------------------------
// Attachment helpers
// ---------------------------------------------------------------------------

/** Field name prefix for attachment binary content (base64-encoded in API). */
export const ATTACHMENT_PREFIX = '_att.';
/** Field name prefix for attachment metadata JSON. */
export const ATTACHMENT_META_PREFIX = '_attmeta.';
/** Maximum raw file size in bytes (768 KiB). */
export const MAX_ATTACHMENT_SIZE = 768 * 1024;
/** Maximum filename length (field name limit minus longest prefix). */
export const MAX_FILENAME_LENGTH = 119;

export function isAttachmentField(name: string): boolean {
  return name.startsWith(ATTACHMENT_PREFIX);
}

export function isAttachmentMetaField(name: string): boolean {
  return name.startsWith(ATTACHMENT_META_PREFIX);
}

export function attachmentFilename(fieldName: string): string {
  if (fieldName.startsWith(ATTACHMENT_PREFIX)) {
    return fieldName.slice(ATTACHMENT_PREFIX.length);
  }
  if (fieldName.startsWith(ATTACHMENT_META_PREFIX)) {
    return fieldName.slice(ATTACHMENT_META_PREFIX.length);
  }
  return '';
}

export function attachmentFieldName(filename: string): string {
  return `${ATTACHMENT_PREFIX}${filename}`;
}

export function attachmentMetaFieldName(filename: string): string {
  return `${ATTACHMENT_META_PREFIX}${filename}`;
}

/** Sanitize a user-provided filename for use as an attachment field name. */
export function sanitizeFilename(name: string): string {
  // Strip path components.
  let base = name.replace(/^.*[/\\]/, '');
  // Replace forbidden characters (colons, double dots).
  base = base.replace(/\.\./g, '_').replace(/[/:]/g, '_');
  return base.slice(0, MAX_FILENAME_LENGTH) || 'unnamed';
}

/** Format a byte count for human display. */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export interface AttachmentMeta {
  content_type: string;
  size: number;
}

export interface AttachmentInfo {
  filename: string;
  meta: AttachmentMeta;
  dataFieldName: string;
}

/** Extract all attachments from an item's fields as a structured list. */
export function itemAttachments(item: VaultItem): AttachmentInfo[] {
  const result: AttachmentInfo[] = [];
  for (const [key, value] of Object.entries(item.fields)) {
    if (isAttachmentMetaField(key)) {
      const filename = attachmentFilename(key);
      const dataFieldName = attachmentFieldName(filename);
      try {
        const meta: AttachmentMeta = JSON.parse(value);
        result.push({ filename, meta, dataFieldName });
      } catch {
        // Skip malformed metadata.
      }
    }
  }
  return result;
}

export interface CAInfo {
  is_ca: boolean;
  is_intermediate: boolean;
  subject: string;
  not_before: string;
  not_after: string;
  next_serial: number;
  crl_number: number;
  cert_count: number;
}

export interface IssueCertResult {
  item_id: string;
  serial_number: string;
  subject: string;
  not_before: string;
  not_after: string;
}

export interface RenewCertResult {
  new_item_id: string;
  old_item_id: string;
  serial_number: string;
}

export interface VaultProfile {
  vaultID: string;
  credentials: string;
  passphrase: string;
  secretKey?: string;
  memberID?: string;
  label?: string;
}

export interface SessionState {
  profiles: VaultProfile[];
  activeVaultID?: string;
}

export interface VaultSummary {
  vault_id: string;
  name?: string;
  description?: string;
  epoch: number;
  item_count: number;
}

export interface HistoryEntry {
  version: number;
  updated_at: string;
  updated_by: string;
}

export interface AuditEntry {
  id: string;
  item_id: string;
  action: 'item_accessed' | 'item_created' | 'item_updated' | 'item_deleted' | 'vault_exported' | 'vault_imported' | 'ca_initialized' | 'cert_issued' | 'cert_revoked' | 'cert_renewed' | 'crl_generated' | 'csr_signed';
  member_id: string;
  created_at: string;
}

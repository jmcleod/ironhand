import { describe, it, expect } from 'vitest';
import { searchItems, groupResultsByVault } from './search';
import { Vault, VaultItem } from '@/types/vault';

function makeItem(id: string, fields: Record<string, string>): VaultItem {
  return { id, fields };
}

function makeVault(id: string, name: string, items: VaultItem[]): Vault {
  return {
    id,
    name,
    description: '',
    items,
    sharedWith: [],
    createdAt: '',
    updatedAt: '',
    epoch: 1,
    itemCount: items.length,
  };
}

const loginItem = makeItem('item-1', {
  _name: 'GitHub Login',
  _type: 'login',
  _created: '2024-01-01T00:00:00Z',
  _updated: '2024-01-01T00:00:00Z',
  username: 'alice@example.com',
  password: 'super-secret-pass',
  url: 'https://github.com',
});

const noteItem = makeItem('item-2', {
  _name: 'Meeting Notes',
  _type: 'note',
  _created: '2024-01-01T00:00:00Z',
  _updated: '2024-01-01T00:00:00Z',
  content: 'Discussed quarterly revenue targets',
});

const cardItem = makeItem('item-3', {
  _name: 'Visa Card',
  _type: 'card',
  _created: '2024-01-01T00:00:00Z',
  _updated: '2024-01-01T00:00:00Z',
  cardholder: 'Alice Smith',
  card_number: '4111111111111111',
  expiry: '12/28',
  cvv: '123',
});

const customItem = makeItem('item-4', {
  _name: 'API Key',
  _type: 'custom',
  _created: '2024-01-01T00:00:00Z',
  _updated: '2024-01-01T00:00:00Z',
  service: 'Stripe',
  key: 'sk_test_abc123',
});

const vault1 = makeVault('vault-1', 'Personal', [loginItem, noteItem]);
const vault2 = makeVault('vault-2', 'Work', [cardItem, customItem]);
const allVaults = [vault1, vault2];

describe('searchItems', () => {
  it('returns all items when query is empty and filter is all', () => {
    const results = searchItems(allVaults, '', 'all');
    expect(results).toHaveLength(4);
  });

  it('matches item by name (case-insensitive)', () => {
    const results = searchItems(allVaults, 'github', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-1');
  });

  it('matches item by name with mixed case', () => {
    const results = searchItems(allVaults, 'MEETING', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-2');
  });

  it('matches item by field value (username)', () => {
    const results = searchItems(allVaults, 'alice@example', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-1');
  });

  it('matches item by field value (url)', () => {
    const results = searchItems(allVaults, 'github.com', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-1');
  });

  it('matches item by field value (note content)', () => {
    const results = searchItems(allVaults, 'quarterly', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-2');
  });

  it('matches item by custom field value', () => {
    const results = searchItems(allVaults, 'stripe', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-4');
  });

  it('does NOT match by sensitive field value (password)', () => {
    const results = searchItems(allVaults, 'super-secret', 'all');
    expect(results).toHaveLength(0);
  });

  it('does NOT match by sensitive field value (cvv)', () => {
    const results = searchItems(allVaults, '123', 'all');
    // Should NOT match card item via cvv.
    // May match other items if "123" appears in non-sensitive fields (e.g. "sk_test_abc123").
    const cardMatch = results.find(r => r.item.id === 'item-3');
    expect(cardMatch).toBeUndefined();
  });

  it('does NOT match by sensitive field value (card_number)', () => {
    const results = searchItems(allVaults, '4111111111', 'all');
    expect(results).toHaveLength(0);
  });

  it('matches item type label', () => {
    const results = searchItems(allVaults, 'login', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-1');
  });

  it('filters by item type', () => {
    const results = searchItems(allVaults, '', 'note');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-2');
  });

  it('combines text query with type filter', () => {
    // Search for "alice" but filter to card type — should not match login
    const results = searchItems(allVaults, 'alice', 'card');
    // "Alice Smith" is the cardholder — should match card
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-3');
  });

  it('returns empty array when no matches', () => {
    const results = searchItems(allVaults, 'xyznonexistent', 'all');
    expect(results).toHaveLength(0);
  });

  it('returns results across multiple vaults', () => {
    const results = searchItems(allVaults, 'alice', 'all');
    // "alice@example.com" in vault1, "Alice Smith" in vault2
    expect(results).toHaveLength(2);
    const vaultIds = results.map(r => r.vault.id);
    expect(vaultIds).toContain('vault-1');
    expect(vaultIds).toContain('vault-2');
  });

  it('trims whitespace from query', () => {
    const results = searchItems(allVaults, '  github  ', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-1');
  });

  it('handles empty vaults array', () => {
    const results = searchItems([], 'test', 'all');
    expect(results).toHaveLength(0);
  });

  it('handles vault with no items', () => {
    const emptyVault = makeVault('empty', 'Empty', []);
    const results = searchItems([emptyVault], 'test', 'all');
    expect(results).toHaveLength(0);
  });
});

describe('searchItems with attachments', () => {
  const attachmentItem = makeItem('item-att', {
    _name: 'SSH Keys',
    _type: 'custom',
    _created: '2024-01-01T00:00:00Z',
    _updated: '2024-01-01T00:00:00Z',
    '_att.id_rsa': 'base64binarydata',
    '_attmeta.id_rsa': '{"content_type":"application/octet-stream","size":1234}',
    note: 'my server key',
  });
  const attVault = makeVault('vault-att', 'Keys', [attachmentItem]);

  it('does NOT match by attachment binary content', () => {
    const results = searchItems([attVault], 'base64binary', 'all');
    expect(results).toHaveLength(0);
  });

  it('matches item with attachment by name', () => {
    const results = searchItems([attVault], 'SSH Keys', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-att');
  });

  it('matches item with attachment by user field', () => {
    const results = searchItems([attVault], 'server key', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-att');
  });

  it('matches item by attachment filename', () => {
    const results = searchItems([attVault], 'id_rsa', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].item.id).toBe('item-att');
  });

  it('does NOT match by attachment metadata JSON content', () => {
    // Searching for "octet-stream" should not match — meta values are not searched,
    // only filenames are.
    const results = searchItems([attVault], 'octet-stream', 'all');
    expect(results).toHaveLength(0);
  });
});

describe('groupResultsByVault', () => {
  it('groups results by vault', () => {
    const results = searchItems(allVaults, '', 'all');
    const grouped = groupResultsByVault(results);
    expect(grouped).toHaveLength(2);
    expect(grouped[0][0].id).toBe('vault-1');
    expect(grouped[0][1]).toHaveLength(2);
    expect(grouped[1][0].id).toBe('vault-2');
    expect(grouped[1][1]).toHaveLength(2);
  });

  it('handles empty results', () => {
    const grouped = groupResultsByVault([]);
    expect(grouped).toHaveLength(0);
  });

  it('handles results from a single vault', () => {
    const results = searchItems(allVaults, 'github', 'all');
    const grouped = groupResultsByVault(results);
    expect(grouped).toHaveLength(1);
    expect(grouped[0][0].id).toBe('vault-1');
    expect(grouped[0][1]).toHaveLength(1);
  });
});

import { Vault, VaultItem, ItemType, itemName, itemType, userFields, SENSITIVE_FIELDS } from '@/types/vault';

export interface SearchResult {
  vault: Vault;
  item: VaultItem;
}

/**
 * Filters items across vaults by text query and/or item type.
 *
 * Text matching is case-insensitive substring against:
 *  - Item name (_name metadata)
 *  - Item type (_type metadata)
 *  - All user-facing field values (excluding sensitive fields like password, cvv, etc.)
 *
 * Sensitive field values are excluded from text matching to avoid leaking
 * secrets through search behavior.
 *
 * Returns a flat array of {vault, item} results.
 */
export function searchItems(
  vaults: Vault[],
  query: string,
  typeFilter: ItemType | 'all' = 'all',
): SearchResult[] {
  const results: SearchResult[] = [];
  const q = query.trim().toLowerCase();

  for (const vault of vaults) {
    for (const item of vault.items) {
      // Apply type filter first (cheap check).
      if (typeFilter !== 'all' && itemType(item) !== typeFilter) {
        continue;
      }

      // If no text query, the item passes (type filter already applied).
      if (!q) {
        results.push({ vault, item });
        continue;
      }

      // Match against item name.
      if (itemName(item).toLowerCase().includes(q)) {
        results.push({ vault, item });
        continue;
      }

      // Match against item type label.
      if (itemType(item).toLowerCase().includes(q)) {
        results.push({ vault, item });
        continue;
      }

      // Match against non-sensitive user field values.
      const fields = userFields(item);
      let matched = false;
      for (const [key, value] of Object.entries(fields)) {
        if (SENSITIVE_FIELDS.has(key)) {
          continue;
        }
        if (value.toLowerCase().includes(q)) {
          matched = true;
          break;
        }
      }
      if (matched) {
        results.push({ vault, item });
      }
    }
  }

  return results;
}

/**
 * Groups search results by vault ID, preserving order.
 * Returns an array of [vault, items[]] tuples.
 */
export function groupResultsByVault(results: SearchResult[]): [Vault, VaultItem[]][] {
  const map = new Map<string, { vault: Vault; items: VaultItem[] }>();
  for (const { vault, item } of results) {
    const existing = map.get(vault.id);
    if (existing) {
      existing.items.push(item);
    } else {
      map.set(vault.id, { vault, items: [item] });
    }
  }
  return Array.from(map.values()).map(({ vault, items }) => [vault, items]);
}

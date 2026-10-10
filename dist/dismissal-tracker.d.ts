import type { Suggestion } from "./types.js";
/**
 * Applies dismissal state to suggestions without mutating the originals.
 * Pure function — no side effects.
 */
export declare function applyDismissals(suggestions: Suggestion[], dismissedIds: Set<string>): Suggestion[];
/**
 * Persistence interface for dismissed suggestion IDs.
 * Allows the core tracker to remain pure while the platform provides storage.
 */
export interface DismissalStore {
    load(): string[];
    save(ids: string[]): void;
}
/**
 * Creates a stateful dismissal tracker with auto-expiry.
 *
 * Dismissals are context-aware: when `apply()` runs, any dismissed IDs
 * not present in the current suggestions are pruned. This means if a user
 * dismisses "close-lock-file", closes the lock file, then reopens it later,
 * the warning reappears.
 */
export declare function createDismissalTracker(store?: DismissalStore): {
    dismiss(id: string): void;
    clear(): void;
    apply(suggestions: Suggestion[]): Suggestion[];
};
//# sourceMappingURL=dismissal-tracker.d.ts.map
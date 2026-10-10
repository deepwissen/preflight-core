/**
 * Applies dismissal state to suggestions without mutating the originals.
 * Pure function — no side effects.
 */
export function applyDismissals(suggestions, dismissedIds) {
    return suggestions.map((s) => ({
        ...s,
        dismissed: dismissedIds.has(s.id),
    }));
}
/**
 * Creates a stateful dismissal tracker with auto-expiry.
 *
 * Dismissals are context-aware: when `apply()` runs, any dismissed IDs
 * not present in the current suggestions are pruned. This means if a user
 * dismisses "close-lock-file", closes the lock file, then reopens it later,
 * the warning reappears.
 */
export function createDismissalTracker(store) {
    const dismissed = new Set(store?.load() ?? []);
    function persist() {
        store?.save([...dismissed]);
    }
    return {
        dismiss(id) {
            dismissed.add(id);
            persist();
        },
        clear() {
            dismissed.clear();
            persist();
        },
        apply(suggestions) {
            // Prune dismissed IDs that are no longer in the current suggestions.
            // This auto-expires dismissals when the underlying condition clears.
            const currentIds = new Set(suggestions.map((s) => s.id));
            let pruned = false;
            for (const id of dismissed) {
                if (!currentIds.has(id)) {
                    dismissed.delete(id);
                    pruned = true;
                }
            }
            if (pruned) {
                persist();
            }
            return applyDismissals(suggestions, dismissed);
        },
    };
}
//# sourceMappingURL=dismissal-tracker.js.map
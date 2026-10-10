/**
 * Typed event bus for decoupled communication between components.
 * No VS Code dependency — works in tests, CLI, and extension.
 */
export class EventBus {
    listeners = new Map();
    on(event, handler) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(handler);
        // Return unsubscribe function
        return () => {
            this.listeners.get(event)?.delete(handler);
        };
    }
    emit(event, data) {
        const handlers = this.listeners.get(event);
        if (!handlers)
            return;
        for (const handler of handlers) {
            try {
                handler(data);
            }
            catch (err) {
                console.error(`[EventBus] Error in handler for "${event}":`, err);
            }
        }
    }
    removeAllListeners() {
        this.listeners.clear();
    }
}
//# sourceMappingURL=event-bus.js.map
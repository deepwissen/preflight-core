import type { EventMap } from "./types.js";
type EventHandler<T> = (data: T) => void;
/**
 * Typed event bus for decoupled communication between components.
 * No VS Code dependency — works in tests, CLI, and extension.
 */
export declare class EventBus {
    private listeners;
    on<K extends keyof EventMap>(event: K, handler: EventHandler<EventMap[K]>): () => void;
    emit<K extends keyof EventMap>(event: K, data: EventMap[K]): void;
    removeAllListeners(): void;
}
export {};
//# sourceMappingURL=event-bus.d.ts.map
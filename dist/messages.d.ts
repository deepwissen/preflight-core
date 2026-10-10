import type { AnalysisResult } from "./types.js";
/**
 * Shared message protocol between extension host and webview.
 *
 * Both sidebar-provider.ts and app.tsx must use these types.
 * This prevents silent breakage when the AnalysisResult shape changes.
 */
export interface AnalysisUpdateMessage {
    type: "analysis-update";
    data: AnalysisResult;
}
export interface DismissSuggestionMessage {
    type: "dismiss-suggestion";
    id: string;
}
export interface ExecuteActionMessage {
    type: "execute-action";
    command: string;
    args?: Record<string, unknown>;
}
export type ExtensionToWebviewMessage = AnalysisUpdateMessage;
export type WebviewToExtensionMessage = DismissSuggestionMessage | ExecuteActionMessage;
//# sourceMappingURL=messages.d.ts.map
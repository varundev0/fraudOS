/**
 * useWebSocket — connects to /ws and broadcasts real-time case events.
 *
 * Features:
 *  - Auto-reconnects with 5-second backoff on disconnect
 *  - On CASE_ADDED or SLA_OVERDUE: invalidates ['investigations'] TanStack Query
 *  - Calls optional onMessage(msg) callback for UI-layer toasts etc.
 *  - Cleans up on unmount
 */

import { useEffect, useRef, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';

export function useWebSocket({ onMessage } = {}) {
  const qc = useQueryClient();
  const wsRef = useRef(null);
  const retryRef = useRef(null);
  const mountedRef = useRef(true);

  // Stable callback reference to avoid tearing down + re-creating the socket
  // every time the parent re-renders with a new inline function.
  const onMessageRef = useRef(onMessage);
  useEffect(() => { onMessageRef.current = onMessage; }, [onMessage]);

  // Self-reference so the reconnect timer can call the latest connect
  // without referencing the const binding inside its own initializer.
  const connectRef = useRef(null);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/ws`;

    let sock;
    try {
      sock = new WebSocket(url);
    } catch {
      // WebSocket constructor can throw in SSR or restricted environments
      return;
    }

    sock.onopen = () => {
      if (retryRef.current) {
        clearTimeout(retryRef.current);
        retryRef.current = null;
      }
    };

    sock.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);

        // Always refresh the case list when something changes
        if (msg.type === 'CASE_ADDED' || msg.type === 'SLA_OVERDUE') {
          qc.invalidateQueries({ queryKey: ['investigations'] });
        }

        // Forward to the caller for toast / banner display
        onMessageRef.current?.(msg);
      } catch {
        // Ignore malformed frames
      }
    };

    sock.onclose = () => {
      if (!mountedRef.current) return;
      // Reconnect after 5 seconds
      retryRef.current = setTimeout(() => connectRef.current?.(), 5000);
    };

    sock.onerror = () => {
      // Let onclose handle the reconnect
      sock.close();
    };

    wsRef.current = sock;
  }, [qc]); // qc is stable

  useEffect(() => { connectRef.current = connect; }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (retryRef.current) {
        clearTimeout(retryRef.current);
        retryRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect loop on intentional unmount
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);
}

/**
 * Time utilities for human-readable timestamps
 */

/**
 * Convert ISO timestamp to human-readable relative time
 * @param {string} isoString - ISO 8601 timestamp
 * @returns {string} Human-readable relative time (e.g., "5m ago", "2h ago")
 */
export function timeAgo(isoString) {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 0) return 'just now'; // future dates
    if (diffSec < 60) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    if (diffDay < 30) return `${Math.floor(diffDay / 7)}w ago`;
    
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return '—';
  }
}

/**
 * Format timestamp for display (short format)
 * @param {string} isoString - ISO 8601 timestamp
 * @returns {string} Formatted time string
 */
export function formatTime(isoString) {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  } catch {
    return '—';
  }
}

/**
 * Format timestamp with both date and time
 * @param {string} isoString - ISO 8601 timestamp  
 * @returns {string} Formatted date/time string
 */
export function formatDateTime(isoString) {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit', 
      minute: '2-digit',
      hour12: false 
    });
  } catch {
    return '—';
  }
}

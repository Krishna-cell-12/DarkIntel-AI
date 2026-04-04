import { useState, useCallback, useRef } from 'react';
import { IconCheck, IconAlert } from './Icons';
import { ToastContext } from './toast-context';

let toastId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const addToast = useCallback((message, type = 'info', duration = 3000) => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, message, type, exiting: false }]);
    timers.current[id] = setTimeout(() => {
      setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
        delete timers.current[id];
      }, 300);
    }, duration);
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    clearTimeout(timers.current[id]);
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 300);
  }, []);

  const icons = { success: <IconCheck style={{ width: 14, height: 14, color: 'var(--low)' }} />, error: <IconAlert style={{ width: 14, height: 14, color: 'var(--critical)' }} />, info: <IconAlert style={{ width: 14, height: 14, color: 'var(--cyan)' }} /> };

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast ${t.type} ${t.exiting ? 'toast-exit' : ''}`} onClick={() => removeToast(t.id)}>
            {icons[t.type]}
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

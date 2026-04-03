import { useState, useEffect } from 'react';

export default function LoadingScreen() {
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setHidden(true), 1500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className={`loading-screen ${hidden ? 'hidden' : ''}`}>
      <div className="loading-logo">
        DARK<span>INTEL</span>
      </div>
      <div className="loading-text">Initializing threat detection systems...</div>
      <div className="loading-bar">
        <div className="loading-bar-fill" />
      </div>
    </div>
  );
}

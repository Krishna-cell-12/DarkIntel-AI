import { useState, useEffect, useCallback, useRef } from 'react';

export default function SplineHero({ onEnter }) {
  const [loaded, setLoaded] = useState(false);
  const hasEnteredRef = useRef(false);

  const triggerEnter = useCallback(() => {
    if (!hasEnteredRef.current) {
      hasEnteredRef.current = true;
      onEnter();
    }
  }, [onEnter]);

  useEffect(() => {
    const handleMessage = (e) => {
      if (e.data === 'spline-loaded') setLoaded(true);
      if (e.data === 'spline-navigate') triggerEnter();
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [triggerEnter]);

  return (
    <section className="spline-hero">
      <div className={`spline-loader ${loaded ? 'loaded' : ''}`}>
        <div className="spline-loader-inner">
          <div className="spline-loader-ring" />
        </div>
      </div>

      <div className="spline-cta-wrap">
        <button className="spline-enter-btn" onClick={triggerEnter}>Enter Terminal</button>
        <button className="spline-skip-btn" onClick={triggerEnter}>Skip Intro</button>
      </div>

      <iframe
        src="/spline-viewer.html"
        className={`spline-iframe ${loaded ? 'visible' : ''}`}
        title="DarkIntel 3D Scene"
        allow="autoplay"
        sandbox="allow-scripts allow-same-origin"
      />
    </section>
  );
}

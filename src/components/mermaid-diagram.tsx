
"use client";

import { useEffect, useState } from 'react';

type MermaidDiagramProps = {
  chart: string;
};

// Add a global declaration for the mermaid object
declare global {
  interface Window {
    mermaid?: any;
  }
}

export function MermaidDiagram({ chart }: MermaidDiagramProps) {
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    if (window.mermaid) {
      setIsLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (isLoaded && chart) {
      let isMounted = true;
      const renderMermaid = async () => {
        try {
          // The mermaid object is now globally available from the CDN script
          window.mermaid.initialize({
            startOnLoad: false,
            theme: 'default',
            securityLevel: 'loose',
          });
          const { svg: renderedSvg } = await window.mermaid.render(`mermaid-${Math.random().toString(36).substring(7)}`, chart);
          if (isMounted) {
            setSvg(renderedSvg);
            setError(null);
          }
        } catch (e: any) {
          console.error("Mermaid rendering error:", e);
          if (isMounted) {
            setError(e.message || "Error rendering diagram.");
            setSvg(null);
          }
        }
      };
      renderMermaid();
      return () => {
        isMounted = false;
      };
    }
  }, [chart, isLoaded]);

  if (error) {
    return (
        <div className="p-4 bg-red-100 text-red-800 rounded-lg">
            <p><strong>Diagram Error:</strong></p>
            <pre className="text-sm whitespace-pre-wrap">{error}</pre>
        </div>
    );
  }

  if (!isLoaded || !svg) {
    return <div>Loading diagram...</div>;
  }

  return <div dangerouslySetInnerHTML={{ __html: svg }} />;
}

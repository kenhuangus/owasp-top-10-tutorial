
"use client";

import { useEffect, useState } from 'react';
import type { Mermaid } from 'mermaid';
import { useTheme } from 'next-themes';

type MermaidDiagramProps = {
  chart: string;
};

export function MermaidDiagram({ chart }: MermaidDiagramProps) {
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const renderMermaid = async () => {
      try {
        const mermaid: Mermaid = (await import('mermaid')).default;
        mermaid.initialize({
          startOnLoad: false,
          theme: 'default',
          securityLevel: 'loose',
        });
        const { svg: renderedSvg } = await mermaid.render(`mermaid-${Math.random().toString(36).substring(7)}`, chart);
        if (isMounted) {
          setSvg(renderedSvg);
          setError(null);
        }
      } catch (e: any) {
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
  }, [chart]);

  if (error) {
    return (
        <div className="p-4 bg-red-100 text-red-800 rounded-lg">
            <p><strong>Diagram Error:</strong></p>
            <pre className="text-sm whitespace-pre-wrap">{error}</pre>
        </div>
    );
  }

  if (!svg) {
    return <div>Loading diagram...</div>;
  }

  return <div dangerouslySetInnerHTML={{ __html: svg }} />;
}

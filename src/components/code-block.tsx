import { cn } from "@/lib/utils";

type CodeBlockProps = {
  code: string;
  language: string;
  className?: string;
};

export function CodeBlock({ code, language, className }: CodeBlockProps) {
  return (
    <div className={cn("relative rounded-lg bg-card border shadow-sm", className)}>
      <div className="absolute top-2 right-3 text-xs uppercase text-muted-foreground font-semibold">{language}</div>
      <pre className="p-4 pt-8 text-sm overflow-x-auto font-code bg-transparent rounded-lg">
        <code
          className="text-foreground"
          dangerouslySetInnerHTML={{ __html: code }}
        />
      </pre>
    </div>
  );
}

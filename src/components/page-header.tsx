import { cn } from "@/lib/utils";

type PageHeaderProps = {
  title: string;
  subtitle?: string;
  className?: string;
};

export function PageHeader({ title, subtitle, className }: PageHeaderProps) {
  return (
    <div className={cn("mb-8 border-b pb-4", className)}>
      <h1 className="font-headline text-3xl md:text-4xl font-bold tracking-tighter text-foreground">
        {title}
      </h1>
      {subtitle && (
        <p className="text-lg text-muted-foreground mt-2 max-w-3xl">
          {subtitle}
        </p>
      )}
    </div>
  );
}

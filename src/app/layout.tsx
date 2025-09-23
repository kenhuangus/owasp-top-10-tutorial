import type { Metadata } from 'next';
import { cn } from '@/lib/utils';
import { Toaster } from '@/components/ui/toaster';
import AppSidebar from '@/components/app-sidebar';
import './globals.css';
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar';
import Script from 'next/script';

export const metadata: Metadata = {
  title: 'OWASPedia',
  description: 'Learn about the OWASP Top 10 vulnerabilities with tutorials, code examples, and diagrams.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=Source+Code+Pro&family=Space+Grotesk:wght@700&display=swap" rel="stylesheet" />
      </head>
      <body className={cn('font-body antialiased min-h-screen bg-background')}>
        <Script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js" strategy="lazyOnload" />
        <SidebarProvider>
          <AppSidebar />
          <SidebarInset>
            <main className="p-4 sm:p-6 lg:p-8">
              {children}
            </main>
          </SidebarInset>
        </SidebarProvider>
        <Toaster />
      </body>
    </html>
  );
}

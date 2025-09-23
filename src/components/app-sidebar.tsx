"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, ShieldCheck, FileText, Bot } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarFooter,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { Button } from './ui/button';
import { Separator } from './ui/separator';

const NAV_ITEMS = [
  { href: '/', label: 'OWASP Top 10', icon: Home },
  { href: '/best-practices', label: 'Best Practices AI', icon: Bot },
];

export default function AppSidebar() {
  const pathname = usePathname();

  return (
    <Sidebar collapsible="icon" className="border-r">
      <SidebarHeader className="h-14 flex items-center justify-between p-2">
        <div className="flex items-center gap-2 [&_span]:hidden group-data-[state=expanded]:[&_span]:inline">
          <Button variant="ghost" size="icon" asChild>
            <Link href="/">
              <ShieldCheck className="text-primary" />
            </Link>
          </Button>
          <span className="font-headline text-lg font-bold">OWASPedia</span>
        </div>
        <SidebarTrigger className="[&_svg]:text-foreground" />
      </SidebarHeader>
      <SidebarContent className="p-2">
        <SidebarMenu>
          {NAV_ITEMS.map((item) => (
            <SidebarMenuItem key={item.href}>
              <SidebarMenuButton
                asChild
                isActive={pathname === item.href}
                tooltip={{ children: item.label, side: 'right' }}
                className={cn(
                  'justify-start',
                  pathname === item.href && 'bg-accent text-accent-foreground'
                )}
              >
                <Link href={item.href}>
                  <item.icon />
                  <span>{item.label}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarContent>
      <SidebarFooter className="p-2">
        <Separator className="my-2" />
        <div className="text-xs text-muted-foreground p-2 [&>span]:hidden group-data-[state=expanded]:[&>span]:inline">
          <span>© {new Date().getFullYear()} OWASPedia</span>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}

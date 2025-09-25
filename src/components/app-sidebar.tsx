"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, ShieldCheck, FileText, Bot, ChevronDown } from 'lucide-react';
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
  SidebarMenuSub,
  SidebarMenuSubButton,
} from '@/components/ui/sidebar';
import { Button } from './ui/button';
import { Separator } from './ui/separator';
import { owaspTop10 } from '@/lib/owasp-data';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import React from 'react';

const NAV_ITEMS = [
  { href: '/', label: 'Home', icon: Home },
  { href: '/best-practices', label: 'Best Practices AI', icon: Bot },
];

const webTop10 = owaspTop10.filter(item => !item.id.startsWith('LLM'));
const llmTop10 = owaspTop10.filter(item => item.id.startsWith('LLM'));


export default function AppSidebar() {
  const pathname = usePathname();

  const isVulnerabilityPage = pathname.startsWith('/vulnerability/');

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
          
          <Collapsible defaultOpen={isVulnerabilityPage}>
             <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton
                  variant="ghost"
                  className="w-full justify-start group"
                  tooltip={{ children: 'OWASP Top 10', side: 'right' }}
                >
                  <ShieldCheck />
                  <span>OWASP Top 10</span>
                  <ChevronDown className="ml-auto h-4 w-4 shrink-0 transition-transform duration-200 group-data-[state=open]:rotate-180" />
                </SidebarMenuButton>
              </CollapsibleTrigger>
            </SidebarMenuItem>

            <CollapsibleContent>
              <SidebarMenuSub>
                {webTop10.map(item => (
                   <SidebarMenuItem key={item.slug}>
                      <SidebarMenuSubButton asChild isActive={pathname === `/vulnerability/${item.slug}`}>
                        <Link href={`/vulnerability/${item.slug}`}>
                          <span>{item.id}: {item.title}</span>
                        </Link>
                      </SidebarMenuSubButton>
                   </SidebarMenuItem>
                ))}
              </SidebarMenuSub>
            </CollapsibleContent>
          </Collapsible>
          
          <Collapsible defaultOpen={isVulnerabilityPage}>
             <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton
                  variant="ghost"
                  className="w-full justify-start group"
                  tooltip={{ children: 'OWASP LLM Top 10', side: 'right' }}
                >
                  <Bot />
                  <span>LLM Top 10</span>
                  <ChevronDown className="ml-auto h-4 w-4 shrink-0 transition-transform duration-200 group-data-[state=open]:rotate-180" />
                </SidebarMenuButton>
              </CollapsibleTrigger>
            </SidebarMenuItem>

            <CollapsibleContent>
              <SidebarMenuSub>
                {llmTop10.map(item => (
                   <SidebarMenuItem key={item.slug}>
                      <SidebarMenuSubButton asChild isActive={pathname === `/vulnerability/${item.slug}`}>
                        <Link href={`/vulnerability/${item.slug}`}>
                          <span>{item.id}: {item.title}</span>
                        </Link>
                      </SidebarMenuSubButton>
                   </SidebarMenuItem>
                ))}
              </SidebarMenuSub>
            </CollapsibleContent>
          </Collapsible>

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

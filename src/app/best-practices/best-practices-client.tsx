"use client";

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { getSecurityBestPracticesAction } from './actions';
import { GenerateSecurityBestPracticesOutput } from '@/ai/flows/generate-security-best-practices';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { useToast } from '@/hooks/use-toast';
import { Loader2, Sparkles } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const formSchema = z.object({
  threatType: z.string().min(3, {
    message: "Threat type must be at least 3 characters.",
  }),
});

export function BestPracticesClient() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GenerateSecurityBestPracticesOutput | null>(null);
  const { toast } = useToast();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      threatType: "",
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setLoading(true);
    setResult(null);
    const response = await getSecurityBestPracticesAction(values.threatType);
    
    if (response.success && response.data) {
      setResult(response.data);
    } else {
      toast({
        variant: "destructive",
        title: "Error",
        description: response.error || "An unknown error occurred.",
      });
    }
    setLoading(false);
  }

  return (
    <div className="space-y-8">
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <FormField
            control={form.control}
            name="threatType"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Threat Type</FormLabel>
                <FormControl>
                  <Input placeholder="e.g., Cross-Site Scripting" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Sparkles className="mr-2 h-4 w-4" />
                Generate Best Practices
              </>
            )}
          </Button>
        </form>
      </Form>

      {result && result.bestPractices.length > 0 && (
        <div className="mt-8">
            <h3 className="text-2xl font-headline font-bold mb-4">Generated Best Practices</h3>
            <Accordion type="single" collapsible className="w-full">
                {result.bestPractices.map((item, index) => (
                    <AccordionItem value={`item-${index}`} key={index}>
                        <AccordionTrigger className="text-left hover:no-underline">
                            {item.practice}
                        </AccordionTrigger>
                        <AccordionContent className="text-muted-foreground">
                           <strong className="text-foreground">Reason:</strong> {item.reason}
                        </AccordionContent>
                    </AccordionItem>
                ))}
            </Accordion>
        </div>
      )}
    </div>
  );
}

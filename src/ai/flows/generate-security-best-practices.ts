'use server';
/**
 * @fileOverview An AI agent that generates security best practices based on the type of threat.
 *
 * - generateSecurityBestPractices - A function that generates security best practices.
 * - GenerateSecurityBestPracticesInput - The input type for the generateSecurityBestPractices function.
 * - GenerateSecurityBestPracticesOutput - The return type for the generateSecurityBestPractices function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const GenerateSecurityBestPracticesInputSchema = z.object({
  threatType: z.string().describe('The type of threat to generate security best practices for.'),
});
export type GenerateSecurityBestPracticesInput = z.infer<typeof GenerateSecurityBestPracticesInputSchema>;

const GenerateSecurityBestPracticesOutputSchema = z.object({
  bestPractices: z.array(z.object({
    practice: z.string().describe('The security best practice.'),
    reason: z.string().describe('The reason for including this security best practice.'),
  })).describe('A list of security best practices and their reasons.'),
});
export type GenerateSecurityBestPracticesOutput = z.infer<typeof GenerateSecurityBestPracticesOutputSchema>;

export async function generateSecurityBestPractices(input: GenerateSecurityBestPracticesInput): Promise<GenerateSecurityBestPracticesOutput> {
  return generateSecurityBestPracticesFlow(input);
}

const prompt = ai.definePrompt({
  name: 'generateSecurityBestPracticesPrompt',
  input: {schema: GenerateSecurityBestPracticesInputSchema},
  output: {schema: GenerateSecurityBestPracticesOutputSchema},
  prompt: `You are an expert in web application security. Generate a list of security best practices for the following type of threat, and explain the reason for including each practice.\n\nThreat Type: {{{threatType}}}`,
});

const generateSecurityBestPracticesFlow = ai.defineFlow({
    name: 'generateSecurityBestPracticesFlow',
    inputSchema: GenerateSecurityBestPracticesInputSchema,
    outputSchema: GenerateSecurityBestPracticesOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);

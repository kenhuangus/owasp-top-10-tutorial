"use server";
import { generateSecurityBestPractices, GenerateSecurityBestPracticesOutput } from '@/ai/flows/generate-security-best-practices';

type ActionResult = {
  success: boolean;
  data?: GenerateSecurityBestPracticesOutput;
  error?: string;
}

export async function getSecurityBestPracticesAction(threatType: string): Promise<ActionResult> {
    if (!threatType || threatType.length < 3) {
      return { success: false, error: 'Threat type must be at least 3 characters long.' };
    }

    try {
        const result = await generateSecurityBestPractices({ threatType });
        if (!result.bestPractices || result.bestPractices.length === 0) {
          return { success: false, error: 'AI could not generate practices for this threat. Please try a different one.' };
        }
        return { success: true, data: result };
    } catch(e) {
        console.error("AI Action Error:", e);
        return { success: false, error: 'An unexpected error occurred while contacting the AI. Please try again later.'};
    }
}

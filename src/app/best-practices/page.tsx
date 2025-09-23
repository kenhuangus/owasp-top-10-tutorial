import { PageHeader } from "@/components/page-header";
import { BestPracticesClient } from "./best-practices-client";
import { Card, CardContent } from "@/components/ui/card";

export default function BestPracticesPage() {
  return (
    <div className="container mx-auto">
      <PageHeader
        title="Security Best Practices AI"
        subtitle="Leverage AI to generate security best practices for any given threat type. Enter a threat (e.g., 'SQL Injection', 'Cross-Site Scripting') to get started."
      />
      <Card>
        <CardContent className="p-6">
          <BestPracticesClient />
        </CardContent>
      </Card>
    </div>
  );
}

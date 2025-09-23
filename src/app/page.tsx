import Link from 'next/link';
import { owaspTop10 } from '@/lib/owasp-data';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { PageHeader } from '@/components/page-header';
import { OwaspIcon } from '@/components/owasp-icon';

export default function Home() {
  return (
    <div className="container mx-auto">
      <PageHeader
        title="Welcome to OWASPedia"
        subtitle="Your guide to understanding and preventing the OWASP Top 10 web application security risks."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {owaspTop10.map((vulnerability) => (
          <Link href={`/vulnerability/${vulnerability.slug}`} key={vulnerability.id}>
            <Card className="h-full hover:border-primary transition-colors duration-300 hover:shadow-lg hover:-translate-y-1">
              <CardHeader>
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-primary/10 rounded-md">
                    <OwaspIcon id={vulnerability.id} className="h-8 w-8 text-primary" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="font-headline text-xl leading-tight">
                      {vulnerability.id}: {vulnerability.title}
                    </CardTitle>
                    <CardDescription className="mt-2">
                      {vulnerability.description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}

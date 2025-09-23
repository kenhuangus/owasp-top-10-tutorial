import {
  ShieldOff,
  KeyRound,
  TerminalSquare,
  DraftingCompass,
  Wrench,
  Component,
  Fingerprint,
  FileCheck2,
  FileClock,
  ServerCog,
  LucideProps,
  Code,
} from 'lucide-react';

const iconMap: Record<string, React.ComponentType<LucideProps>> = {
  A01: ShieldOff,
  A02: KeyRound,
  'A03-SQLi': TerminalSquare,
  'A03-XSS': Code,
  A04: DraftingCompass,
  A05: Wrench,
  A06: Component,
  A07: Fingerprint,
  A08: FileCheck2,
  A09: FileClock,
  A10: ServerCog,
};

type OwaspIconProps = LucideProps & {
  id: string;
};

export function OwaspIcon({ id, ...props }: OwaspIconProps) {
  const IconComponent = iconMap[id];

  if (!IconComponent) {
    return <ShieldOff {...props} />; // Default icon
  }

  return <IconComponent {...props} />;
}

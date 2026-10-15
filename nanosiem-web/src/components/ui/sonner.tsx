// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTheme } from 'next-themes';
import { Toaster as Sonner } from 'sonner';

import { sonnerAppearance } from '@/lib/theme';

type ToasterProps = React.ComponentProps<typeof Sonner>;

const Toaster = ({ ...props }: ToasterProps) => {
  const { resolvedTheme } = useTheme();

  return <Sonner theme={sonnerAppearance(resolvedTheme)} {...props} />;
};

export { Toaster };

// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTheme } from 'next-themes';
import { useEffect, useState } from 'react';

interface LogoProps {
  className?: string;
  alt?: string;
  size?: 'small' | 'normal';
}

export function Logo({ className = "w-10 h-10", alt = "nano", size = 'normal' }: LogoProps) {
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  
  // Avoid hydration mismatch by only rendering after mount
  useEffect(() => {
    setMounted(true);
  }, []);
  
  if (!mounted) {
    // Return a placeholder to avoid layout shift
    return <div className={className} />;
  }
  
  // Use resolvedTheme to handle 'system' theme properly
  // Use light theme logo (dark colors) for light mode
  // Use dark theme logo (light colors) for dark mode
  let logoSrc: string;
  if (size === 'small') {
    logoSrc = resolvedTheme === 'dark' ? '/logo_small_dark_theme.svg' : '/logo_small_light_theme.svg';
  } else {
    logoSrc = resolvedTheme === 'dark' ? '/logo_dark_theme.svg' : '/logo_light_theme.svg';
  }
  
  return (
    <img 
      src={logoSrc} 
      alt={alt} 
      className={`${className} object-contain`}
      style={{ objectPosition: 'center' }}
    />
  );
}
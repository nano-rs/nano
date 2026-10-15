// SPDX-License-Identifier: AGPL-3.0-or-later

import { ThemeProvider as NextThemesProvider } from "next-themes"

import { THEMES, type Theme } from "@/lib/theme"

interface ThemeProviderProps {
  children: React.ReactNode
  defaultTheme?: Theme | "system"
  storageKey?: string
  attribute?: "class" | "data-theme"
}

export function ThemeProvider({
  children,
  defaultTheme = "dark",
  storageKey = "nanosiem-theme",
  attribute = "class",
  ...props
}: ThemeProviderProps) {
  return (
    <NextThemesProvider
      attribute={attribute}
      // next-themes only writes classes for themes it knows about; without this
      // `matte` would be selectable and never actually applied.
      themes={[...THEMES]}
      defaultTheme={defaultTheme}
      storageKey={storageKey}
      enableSystem
      disableTransitionOnChange
      {...props}
    >
      {children}
    </NextThemesProvider>
  )
}

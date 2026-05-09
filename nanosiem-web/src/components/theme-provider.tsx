// SPDX-License-Identifier: AGPL-3.0-or-later

import { ThemeProvider as NextThemesProvider } from "next-themes"

interface ThemeProviderProps {
  children: React.ReactNode
  defaultTheme?: "light" | "dark" | "system"
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

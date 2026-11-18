using MudBlazor;

namespace Auth.Client.Layout;

/// <summary>
/// Design System centralizado do Auth Manager (IAM / security-first).
/// Nunca hardcodar cores em páginas: use Color.* e variáveis --mud-palette-*.
/// Ver docs/ui-ux-guidelines.md.
/// </summary>
public static class AuthTheme
{
    public static readonly MudTheme Default = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#2563EB",
            PrimaryDarken = "#1D4ED8",
            Secondary = "#475569",
            Tertiary = "#0EA5E9",
            Info = "#3B82F6",
            Success = "#059669",
            Warning = "#D97706",
            Error = "#DC2626",
            Background = "#F8FAFC",
            BackgroundGray = "#F1F5F9",
            Surface = "#FFFFFF",
            AppbarBackground = "#0F172A",
            AppbarText = "#F8FAFC",
            DrawerBackground = "#0F172A",
            DrawerText = "#CBD5E1",
            DrawerIcon = "#94A3B8",
            TextPrimary = "#0F172A",
            TextSecondary = "#475569",
            LinesDefault = "#E2E8F0",
            TableLines = "#E2E8F0",
            Divider = "#E2E8F0",
            ActionDefault = "#475569"
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "8px",
            DrawerWidthLeft = "260px"
        },
        Typography = new Typography
        {
            Default = new DefaultTypography
            {
                FontFamily = new[] { "Inter", "Roboto", "Helvetica", "Arial", "sans-serif" }
            },
            H5 = new H5Typography { FontWeight = "600" },
            H6 = new H6Typography { FontWeight = "600" },
            Button = new ButtonTypography { TextTransform = "none", FontWeight = "500" }
        }
    };
}

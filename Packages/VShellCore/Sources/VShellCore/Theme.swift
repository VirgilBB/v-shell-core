import Foundation

/// Terminal colour themes as plain hex data. v-Shell Green, Classic and Amber are v-Shell's own;
/// the others follow their published (MIT-licensed) palettes, credited in Acknowledgements.
public struct Theme: Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let background: String
    public let foreground: String
    public let cursor: String
    public let selection: String
    /// 16 ANSI colours, 0-15.
    public let ansi: [String]

    public static let all: [Theme] = [matrix, classic_dark, classic_light, solarized_dark, solarized_light, dracula, nord, gruvbox_dark, one_dark, tokyo_night, catppuccin_mocha, catppuccin_latte, amber]
    public static let `default` = matrix
    /// Theme ids from earlier versions map to their closest current theme.
    static let renamed = ["paper": "classic-light", "midnight": "tokyo-night", "solar-dark": "solarized-dark", "vampire": "dracula"]
    public static func named(_ id: String) -> Theme {
        let id = renamed[id] ?? id
        return all.first { $0.id == id } ?? .default
    }

    /// Light background: the app switches the keyboard and key bar to light to match.
    public var isLight: Bool {
        let (r, g, b) = Theme.rgb(background)
        return (0.299 * Double(r) + 0.587 * Double(g) + 0.114 * Double(b)) / 255 > 0.5
    }

    public static let matrix = Theme(id: "matrix", name: "v-Shell Green", background: "#000000", foreground: "#00FF00",
        cursor: "#C8FFC8", selection: "#1E5B1E",
        ansi: ["#000000", "#FF5555", "#00FF00", "#E5E510", "#3B8EEA", "#D670D6", "#29B8DB", "#C8FFC8",
               "#666666", "#FF7777", "#55FF55", "#F5F543", "#5CA8FF", "#E890E8", "#4FD6F0", "#FFFFFF"])
    public static let classic_dark = Theme(id: "classic-dark", name: "Classic Dark", background: "#000000", foreground: "#E5E5E5",
        cursor: "#FFFFFF", selection: "#3A3A3A",
        ansi: ["#000000", "#CD3131", "#0DBC79", "#E5E510", "#3B8EEA", "#BC3FBC", "#11A8CD", "#E5E5E5",
               "#666666", "#F14C4C", "#23D18B", "#F5F543", "#3B8EEA", "#D670D6", "#29B8DB", "#FFFFFF"])
    public static let classic_light = Theme(id: "classic-light", name: "Classic Light", background: "#FFFFFF", foreground: "#000000",
        cursor: "#000000", selection: "#ADD6FF",
        ansi: ["#000000", "#CD3131", "#00BC00", "#949800", "#0451A5", "#BC05BC", "#0598BC", "#555555",
               "#666666", "#CD3131", "#14CE14", "#B5BA00", "#0451A5", "#BC05BC", "#0598BC", "#A5A5A5"])
    public static let solarized_dark = Theme(id: "solarized-dark", name: "Solarized Dark", background: "#002B36", foreground: "#839496",
        cursor: "#93A1A1", selection: "#073642",
        ansi: ["#073642", "#DC322F", "#859900", "#B58900", "#268BD2", "#D33682", "#2AA198", "#EEE8D5",
               "#586E75", "#CB4B16", "#586E75", "#657B83", "#839496", "#6C71C4", "#93A1A1", "#FDF6E3"])
    public static let solarized_light = Theme(id: "solarized-light", name: "Solarized Light", background: "#FDF6E3", foreground: "#586E75",
        cursor: "#586E75", selection: "#EEE8D5",
        ansi: ["#073642", "#DC322F", "#859900", "#B58900", "#268BD2", "#D33682", "#2AA198", "#EEE8D5",
               "#586E75", "#CB4B16", "#586E75", "#657B83", "#839496", "#6C71C4", "#93A1A1", "#FDF6E3"])
    public static let dracula = Theme(id: "dracula", name: "Dracula", background: "#282A36", foreground: "#F8F8F2",
        cursor: "#F8F8F2", selection: "#44475A",
        ansi: ["#21222C", "#FF5555", "#50FA7B", "#F1FA8C", "#BD93F9", "#FF79C6", "#8BE9FD", "#F8F8F2",
               "#6272A4", "#FF6E6E", "#69FF94", "#FFFFA5", "#D6ACFF", "#FF92DF", "#A4FFFF", "#FFFFFF"])
    public static let nord = Theme(id: "nord", name: "Nord", background: "#2E3440", foreground: "#D8DEE9",
        cursor: "#D8DEE9", selection: "#434C5E",
        ansi: ["#3B4252", "#BF616A", "#A3BE8C", "#EBCB8B", "#81A1C1", "#B48EAD", "#88C0D0", "#E5E9F0",
               "#4C566A", "#BF616A", "#A3BE8C", "#EBCB8B", "#81A1C1", "#B48EAD", "#8FBCBB", "#ECEFF4"])
    public static let gruvbox_dark = Theme(id: "gruvbox-dark", name: "Gruvbox Dark", background: "#282828", foreground: "#EBDBB2",
        cursor: "#EBDBB2", selection: "#504945",
        ansi: ["#282828", "#CC241D", "#98971A", "#D79921", "#458588", "#B16286", "#689D6A", "#A89984",
               "#928374", "#FB4934", "#B8BB26", "#FABD2F", "#83A598", "#D3869B", "#8EC07C", "#EBDBB2"])
    public static let one_dark = Theme(id: "one-dark", name: "One Dark", background: "#282C34", foreground: "#ABB2BF",
        cursor: "#528BFF", selection: "#3E4451",
        ansi: ["#282C34", "#E06C75", "#98C379", "#E5C07B", "#61AFEF", "#C678DD", "#56B6C2", "#ABB2BF",
               "#5C6370", "#E06C75", "#98C379", "#E5C07B", "#61AFEF", "#C678DD", "#56B6C2", "#FFFFFF"])
    public static let tokyo_night = Theme(id: "tokyo-night", name: "Tokyo Night", background: "#1A1B26", foreground: "#C0CAF5",
        cursor: "#C0CAF5", selection: "#33467C",
        ansi: ["#15161E", "#F7768E", "#9ECE6A", "#E0AF68", "#7AA2F7", "#BB9AF7", "#7DCFFF", "#A9B1D6",
               "#414868", "#F7768E", "#9ECE6A", "#E0AF68", "#7AA2F7", "#BB9AF7", "#7DCFFF", "#C0CAF5"])
    public static let catppuccin_mocha = Theme(id: "catppuccin-mocha", name: "Catppuccin Mocha", background: "#1E1E2E", foreground: "#CDD6F4",
        cursor: "#F5E0DC", selection: "#585B70",
        ansi: ["#45475A", "#F38BA8", "#A6E3A1", "#F9E2AF", "#89B4FA", "#F5C2E7", "#94E2D5", "#BAC2DE",
               "#585B70", "#F38BA8", "#A6E3A1", "#F9E2AF", "#89B4FA", "#F5C2E7", "#94E2D5", "#A6ADC8"])
    public static let catppuccin_latte = Theme(id: "catppuccin-latte", name: "Catppuccin Latte", background: "#EFF1F5", foreground: "#4C4F69",
        cursor: "#DC8A78", selection: "#ACB0BE",
        ansi: ["#5C5F77", "#D20F39", "#40A02B", "#DF8E1D", "#1E66F5", "#EA76CB", "#179299", "#ACB0BE",
               "#6C6F85", "#D20F39", "#40A02B", "#DF8E1D", "#1E66F5", "#EA76CB", "#179299", "#BCC0CC"])
    public static let amber = Theme(id: "amber", name: "Amber CRT", background: "#120B00", foreground: "#FFB000",
        cursor: "#FFCC66", selection: "#4A3300",
        ansi: ["#120B00", "#FF6A00", "#FFB000", "#FFCC00", "#CC8800", "#FF9955", "#FFD27F", "#FFE0A0",
               "#5C4000", "#FF8833", "#FFC233", "#FFDD55", "#E0A030", "#FFB080", "#FFE0A8", "#FFF2D0"])

    /// "#RRGGBB" -> (r, g, b) in 0...255
    public static func rgb(_ hex: String) -> (UInt8, UInt8, UInt8) {
        let h = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        guard h.count == 6, let v = UInt32(h, radix: 16) else { return (0, 0, 0) }
        return (UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF))
    }
}

# turbopuffer brand palette (primary sampled from the official logo kit)
# Powerpipe can't inject CSS or fonts, so the brand look comes from three
# levers: this palette on every chart, box-drawing "label on the border"
# panels in monospace code fences (matching the site's framed sections),
# and dynamic amber/ok card states.

locals {
  puffer_amber = "#FB915F" # official logo orange (matches plugin brand_color)
  puffer_deep  = "#D2743E" # hover/darker amber
  puffer_brown = "#8C5A2B" # earth accent
  puffer_sand  = "#E8D9C3" # warm neutral
  puffer_mist  = "#D8D2C8" # muted grey for "default"/inactive
  puffer_ink   = "#141414" # near-black text
  puffer_coral = "#E07856" # alerts (their Delete-button salmon, deepened)
}

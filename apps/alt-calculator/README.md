# Alt Calculator Docker Image

A simple and flexible calculator for property bookings with configurable rates.

## Quick Start (2 minutes)

1. Create a new directory and download the required files:
```bash
mkdir alt-calculator && cd alt-calculator
curl -O https://raw.githubusercontent.com/yourusername/alt-calculator/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/yourusername/alt-calculator/main/config/prices.json
```

2. Start the calculator:
```bash
docker-compose up -d
```

That's it! Visit http://localhost:3000 to use the calculator.

## Configuring Prices

Simply edit the `prices.json` file. The structure is straightforward:

```json
{
  "properties": {
    "Property Name": {
      "Room Type": {
        "Rack": price,
        "High": price,
        "Medium": price,
        "Low": price
      }
    }
  }
}
```

After editing prices:
```bash
docker-compose restart
```

## Features

- Easy price configuration - just edit a simple JSON file
- Automatic calculations for:
  - Long-stay discounts (9-18 nights: 20%, 19-28 nights: 35%, 29+ nights: 50%)
  - Double occupancy (+20%)
  - VAT (7%)
  - Extra discounts
- Multiple properties and room types
- Booking extensions and room changes
- Detailed price breakdowns

## Example Configuration

Here's a simple example of setting prices for one room type:

```json
{
  "properties": {
    "My Property": {
      "Standard Room": {
        "Rack": 2000,
        "High": 1800,
        "Medium": 1600,
        "Low": 1400
      }
    }
  }
}
```

## Need Help?

- GitHub Issues: [link to your repo]
- Documentation: [link to your docs]
- Docker Hub: [link to your image] 
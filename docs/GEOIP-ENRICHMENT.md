# GeoIP Enrichment Setup

## Overview
GeoIP enrichment adds geographic location data to honeypot logs, enabling visualization of attack origins on a world map.

## Prerequisites
- Logstash running
- GeoIP database (MaxMind or similar)

## Step 1: Download GeoIP Database

### Option A: MaxMind GeoLite2 (Free)
```bash
# Register at: https://www.maxmind.com/en/geolite2/geolite2-free-download-form
# Download GeoLite2-City.tar.gz
# Extract to: /usr/share/GeoIP/GeoLite2-City.mmdb
```

### Option B: IP2Location (Free)
```bash
# Download from: https://www.ip2location.com/
# Extract to: /usr/share/GeoIP/IP2LOCATION-LITE-DB3.BIN
```

## Step 2: Update Logstash Configuration

Add to logstash.conf filters section:

```logstash
# Enrich with GeoIP data
if [src_ip] {
  geoip {
    source => "src_ip"
    target => "geoip"
    database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
  }
}

# For OpenCanary
if [source_ip] {
  geoip {
    source => "source_ip"
    target => "geoip"
    database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
  }
}
```

## Step 3: Create Kibana Visualization

1. Go to Kibana: http://localhost:5601
2. Create new visualization: "Geo Map"
3. Select index: honeypot-*
4. Geo field: geoip.location
5. Metric: Count of events

Result: World map showing attack origins

## Available GeoIP Fields

After enrichment, these fields are available in Kibana:
- `geoip.location` — Latitude/Longitude coordinates
- `geoip.country_name` — Country of attacker
- `geoip.city_name` — City of attacker
- `geoip.continent_name` — Continent
- `geoip.region_code` — State/Province

## Example Query in Kibana

```json
GET honeypot-*/_search
{
  "aggs": {
    "attack_by_country": {
      "terms": {
        "field": "geoip.country_name",
        "size": 10
      }
    }
  }
}
```

## Troubleshooting

### "GeoIP database not found"
- Download database from MaxMind
- Place in /usr/share/GeoIP/
- Restart Logstash

### No geoip fields in logs
- Check Logstash logs: `docker-compose logs logstash`
- Verify source IP field name matches config
- Restart Logstash after config change

## Performance Notes

- GeoIP lookup adds ~1-2ms per event
- Cache enabled by default in Logstash
- For high-volume deployments, consider Redis cache

## Next Steps

1. Set up GeoIP database
2. Update Logstash config
3. Create Kibana geo map visualization
4. Monitor attack origins in real-time


# Kibana Query Examples for Attack Analysis

## 1. Top 10 Attacking IP Addresses

```json
GET honeypot-*/_search
{
  "size": 0,
  "aggs": {
    "top_attacker_ips": {
      "terms": {
        "field": "src_ip",
        "size": 10,
        "order": {
          "_count": "desc"
        }
      }
    }
  }
}
```

**Use case**: Identify most persistent attackers

---

## 2. Failed Login Attempts Timeline

```json
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "login_attempt" } }
      ]
    }
  },
  "aggs": {
    "login_attempts_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      }
    }
  }
}
```

**Use case**: Track attack patterns by time of day

---

## 3. Captured Credentials

```json
GET honeypot-*/_search
{
  "query": {
    "exists": {
      "field": "logdata.PASSWORD"
    }
  },
  "size": 100,
  "_source": ["logdata.USERNAME", "logdata.PASSWORD", "@timestamp", "honeypot_type"]
}
```

**Use case**: See all credentials attempted/captured

---

## 4. Commands Executed on Cowrie

```json
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "honeypot_type": "cowrie_ssh" } },
        { "exists": { "field": "logdata.CMD" } }
      ]
    }
  },
  "size": 50,
  "_source": ["logdata.CMD", "logdata.USERNAME", "@timestamp"]
}
```

**Use case**: Analyze attacker behavior and command execution

---

## 5. Attack Distribution by Service

```json
GET honeypot-*/_search
{
  "size": 0,
  "aggs": {
    "by_service": {
      "terms": {
        "field": "service",
        "size": 10
      }
    }
  }
}
```

**Use case**: Which services are most targeted?

---

## 6. HTTP Requests to Honeypot

```json
GET honeypot-*/_search
{
  "query": {
    "term": {
      "event_type": "http_request"
    }
  },
  "aggs": {
    "top_paths": {
      "terms": {
        "field": "logdata.PATH",
        "size": 10
      }
    }
  }
}
```

**Use case**: What URLs are attackers probing?

---

## 7. User Agents Analysis

```json
GET honeypot-*/_search
{
  "query": {
    "exists": {
      "field": "logdata.USERAGENT"
    }
  },
  "aggs": {
    "top_user_agents": {
      "terms": {
        "field": "logdata.USERAGENT",
        "size": 10
      }
    }
  }
}
```

**Use case**: Identify scanner tools and bots

---

## 8. Attack Volume by Day

```json
GET honeypot-*/_search
{
  "size": 0,
  "aggs": {
    "daily_volume": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "day"
      }
    }
  }
}
```

**Use case**: Track attack trends over time

---

## 9. Geographic Distribution (with GeoIP)

```json
GET honeypot-*/_search
{
  "size": 0,
  "aggs": {
    "by_country": {
      "terms": {
        "field": "geoip.country_name",
        "size": 20
      }
    }
  }
}
```

**Use case**: Which countries are attacking most?

---

## 10. Real-time Alert Query

```json
GET honeypot-*/_search
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-5m"
      }
    }
  },
  "sort": [
    { "@timestamp": { "order": "desc" } }
  ]
}
```

**Use case**: Last 5 minutes of attacks (for alerts)


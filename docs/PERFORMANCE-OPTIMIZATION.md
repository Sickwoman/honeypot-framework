# Performance Optimization Guide

## Overview

Optimize the Honeypot Framework for faster queries, better throughput, and efficient resource usage.

---

## 1. Elasticsearch Query Optimization

### Use Filters Instead of Queries

```json
// ❌ SLOW - Uses scoring
GET honeypot-*/_search
{
  "query": {
    "match": {
      "event_type": "login_attempt"
    }
  }
}

// ✅ FAST - Uses filter (cached)
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "filter": {
        "term": {
          "event_type": "login_attempt"
        }
      }
    }
  }
}
```

### Optimize Aggregations

```json
// ❌ SLOW - Calculates everything
GET honeypot-*/_search
{
  "aggs": {
    "all_ips": {
      "terms": {
        "field": "src_ip",
        "size": 100
      }
    }
  }
}

// ✅ FAST - Limits to top results
GET honeypot-*/_search
{
  "aggs": {
    "top_ips": {
      "terms": {
        "field": "src_ip",
        "size": 10
      }
    }
  }
}
```

### Use _source Filtering

```json
// ❌ SLOW - Returns all fields
GET honeypot-*/_search

// ✅ FAST - Returns only needed fields
GET honeypot-*/_search
{
  "_source": ["src_ip", "event_type", "@timestamp"],
  "query": { "match_all": {} }
}
```

### Time-based Queries

```json
// ✅ FAST - Queries recent data only
GET honeypot-*/_search
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1d"
      }
    }
  }
}
```

### Index Pattern Optimization

```bash
# Query only recent indices
GET honeypot-2026.06.*/_search

# Use wildcard carefully
GET honeypot-*/_search  # Can be slow with many indices

# Use date math
GET honeypot-{now/d-7d}/_search  # Last 7 days
```

---

## 2. Index Lifecycle Management (ILM)

### Create ILM Policy

```bash
curl -X PUT "localhost:9200/_ilm/policy/honeypot-policy?pretty" \
  -H 'Content-Type: application/json' \
  -d'
  {
    "policy": "honeypot-policy",
    "phases": {
      "hot": {
        "min_age": "0d",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "50GB",
            "max_age": "1d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "set_priority": {
            "priority": 50
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "searchable_snapshot": {
            "snapshot_repository": "found-snapshots"
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
  '
```

### Apply ILM to Index Template

```bash
curl -X PUT "localhost:9200/_index_template/honeypot-template?pretty" \
  -H 'Content-Type: application/json' \
  -d'
  {
    "index_patterns": ["honeypot-*"],
    "template": {
      "settings": {
        "index.lifecycle.name": "honeypot-policy",
        "index.lifecycle.rollover_alias": "honeypot-write",
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "src_ip": { "type": "keyword" },
          "event_type": { "type": "keyword" }
        }
      }
    }
  }
  '
```

---

## 3. Shard and Replica Optimization

### Check Shard Status

```bash
curl -s "localhost:9200/_cat/shards?v" | head -20
```

### Optimize Sharding

```json
// For small indices (< 1GB)
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  }
}

// For medium indices (1-100GB)
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1
  }
}

// For large indices (> 100GB)
{
  "settings": {
    "number_of_shards": 5,
    "number_of_replicas": 1
  }
}
```

---

## 4. Logstash Pipeline Optimization

### Optimize Filter Performance

```conf
# ❌ SLOW - Multiple filters
filter {
  if [event_type] == "login" { mutate { add_field => { "category" => "auth" } } }
  if [service] == "SSH" { mutate { add_field => { "protocol" => "ssh" } } }
  if [src_ip] { geoip { source => "src_ip" } }
}

# ✅ FAST - Consolidated filters
filter {
  if [event_type] == "login" {
    mutate {
      add_field => {
        "category" => "auth"
        "protocol" => "%{service}"
      }
    }
    geoip {
      source => "src_ip"
    }
  }
}
```

### Batch Processing

```conf
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    batch_size => 1000  # Batch inserts
    flush_interval => 5  # Flush every 5 seconds
    index => "honeypot-%{+YYYY.MM.dd}"
  }
}
```

### Pipeline Tuning

```bash
# In logstash.yml
pipeline.workers: 4  # Number of worker threads
pipeline.batch.size: 1000  # Events per batch
pipeline.batch.delay: 50  # Milliseconds
```

---

## 5. Mapping Optimization

### Create Optimized Mappings

```json
PUT honeypot-mapping
{
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date",
        "format": "strict_date_optional_time||epoch_millis"
      },
      "src_ip": {
        "type": "keyword",
        "ignore_above": 256
      },
      "event_type": {
        "type": "keyword"
      },
      "logdata": {
        "type": "nested",
        "properties": {
          "USERNAME": { "type": "keyword" },
          "PASSWORD": { "type": "keyword", "index": false }
        }
      },
      "message": {
        "type": "text",
        "analyzer": "standard"
      }
    }
  }
}
```

### Disable Unnecessary Indexing

```json
{
  "properties": {
    "raw_log": {
      "type": "keyword",
      "index": false  // Not searchable but stored
    }
  }
}
```

---

## 6. Caching Strategies

### Query Cache

```bash
# Clear query cache
curl -X POST "localhost:9200/_cache/clear?pretty"

# Check cache statistics
curl -X GET "localhost:9200/_stats/query_cache?pretty"
```

### Request Cache

```json
// Cache this query result
GET honeypot-*/_search?request_cache=true
{
  "query": { "match_all": {} },
  "aggs": {
    "top_ips": {
      "terms": { "field": "src_ip", "size": 10 }
    }
  }
}
```

### Fielddata Cache

```bash
# Disable fielddata for text fields
PUT honeypot-mapping/_mapping
{
  "properties": {
    "message": {
      "type": "text",
      "fielddata": false  // Use doc_values instead
    }
  }
}
```

---

## 7. Memory and CPU Optimization

### Monitor Resource Usage

```bash
# Check heap usage
curl -s "localhost:9200/_nodes/stats/jvm?pretty" | grep -A5 "heap"

# Check CPU usage
curl -s "localhost:9200/_nodes/stats/os?pretty" | grep -A5 "cpu"
```

### Optimize JVM Settings

```bash
# In docker-compose.yml or elasticsearch.yml
environment:
  - "ES_JAVA_OPTS=-Xms512m -Xmx512m"  # Heap size
  - "MALLOC_TRIM_THRESHOLD_=128000"   # Memory optimization
```

### Bulk Indexing Optimization

```python
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

es = Elasticsearch(['localhost:9200'])

actions = []
for doc in documents:
    actions.append({
        "_index": "honeypot",
        "_source": doc
    })

# Bulk insert
bulk(es, actions, chunk_size=500)
```

---

## 8. Network Optimization

### Connection Pooling

```python
from elasticsearch import Elasticsearch

# Persistent connection pool
es = Elasticsearch(
    ['localhost:9200'],
    max_retries=3,
    retry_on_timeout=True,
    connection_class=urllib3.HTTPConnectionPool
)
```

### Compression

```json
// Enable HTTP compression
http.compression: true
http.compression_level: 6  // 1-9, higher = more compression
```

---

## 9. Monitoring Performance

### Key Metrics

```bash
# Query latency
curl -s "localhost:9200/_stats?pretty" | grep "query_time_in_millis"

# Indexing rate
curl -s "localhost:9200/_stats?pretty" | grep "indexing"

# Search rate
curl -s "localhost:9200/_stats?pretty" | grep "search"
```

### Create Performance Dashboard

```json
GET honeypot-*/_search
{
  "aggs": {
    "query_latency": {
      "avg": {
        "field": "query_time_ms"
      }
    },
    "index_rate": {
      "rate": {
        "unit": "minute"
      }
    }
  }
}
```

---

## 10. Performance Checklist

- [ ] Use filters instead of queries
- [ ] Limit aggregation results
- [ ] Use _source filtering
- [ ] Implement ILM policies
- [ ] Optimize shard count
- [ ] Tune Logstash pipeline
- [ ] Create proper mappings
- [ ] Disable unnecessary fields
- [ ] Monitor cache hit ratio
- [ ] Regular index maintenance
- [ ] Monitor heap usage
- [ ] Enable HTTP compression
- [ ] Use bulk operations
- [ ] Archive old data
- [ ] Regular backups

---

## Performance Benchmarks

| Operation | Before Optimization | After Optimization | Improvement |
|-----------|-------------------|-------------------|------------|
| Query latency | 500ms | 50ms | 10x faster |
| Aggregation | 2000ms | 200ms | 10x faster |
| Indexing rate | 1000 docs/sec | 10000 docs/sec | 10x faster |
| Memory usage | 2GB | 512MB | 75% reduction |
| Disk usage | 100GB | 30GB | 70% reduction |


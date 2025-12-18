# pfelg

PNsense/pfSense firewall log analysis with GeoIP visualization for Grafana.

Inspired by [pfelk](https://github.com/pfelk/pfelk) but simplified: **no custom scripts, just the official Elasticsearch and Logstash Docker images** with configuration files.

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.17.0-blue)
![Logstash](https://img.shields.io/badge/Logstash-8.17.0-yellow)

## Features

- Firewall log parsing (block/pass events)
- GeoIP enrichment with map visualization
- Minimal RAM footprint (~1.5 GB total)
- Automatic data retention via ILM
- ECS-compliant field structure

## Architecture

```
OPNsense ──── Syslog (RFC5424, UDP 5140) ────► Logstash ────► Elasticsearch ────► Grafana
                                               (GeoIP)        (Storage)          (Dashboards)
```

## Prerequisites

- Docker
- MaxMind GeoLite2 databases (free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup))

## Installation

### 1. Directory Structure

```
/your/path/pfelg/
├── elasticsearch/
├── logstash/
│   ├── config/
│   │   └── logstash.yml
│   ├── pipeline/
│   │   ├── 01-inputs.conf
│   │   ├── 02-firewall.conf
│   │   ├── 05-apps.conf
│   │   ├── 30-geoip.conf
│   │   ├── 49-cleanup.conf
│   │   └── 50-outputs.conf
│   └── patterns/
│       ├── pfelk.grok
│       └── openvpn.grok
└── maxmind/
    ├── GeoLite2-City.mmdb
    └── GeoLite2-ASN.mmdb
```

Copy all files from this repository to the corresponding directories. Download MaxMind databases and place them in the `maxmind/` folder.


### 2. Elasticsearch

```bash
docker run -d \
  --name pfelg-elasticsearch \
  -p 9200:9200 \
  -v /your/path/pfelg/elasticsearch:/usr/share/elasticsearch/data \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms256m -Xmx256m" \
  -e "cluster.name=pfelg" \
  --ulimit memlock=-1:-1 \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.0
```

### 3. Logstash

```bash
docker run -d \
  --name pfelg-logstash \
  --link pfelg-elasticsearch:elasticsearch \
  -p 5140:5140/udp \
  -p 5140:5140/tcp \
  -v /your/path/pfelg/logstash/pipeline:/usr/share/logstash/pipeline:ro \
  -v /your/path/pfelg/logstash/patterns:/usr/share/logstash/patterns:ro \
  -v /your/path/pfelg/logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro \
  -v /your/path/pfelg/maxmind:/usr/share/logstash/maxmind:ro \
  -e "LS_JAVA_OPTS=-Xms256m -Xmx256m" \
  -e "XPACK_MONITORING_ENABLED=false" \
  docker.elastic.co/logstash/logstash:8.17.0
```

### 4. ILM Policy


#### Konzept

```
┌─────────┐    ┌─────────┐    ┌─────────┐
│   HOT   │ →  │  WARM   │ →  │  COLD   │ →  (optional: DELETE)
│  0-24h  │    │  1-7d   │    │   7d+   │
│  fast   │    │ Compress│    │  Archiv │
└─────────┘    └─────────┘    └─────────┘
```

Choose a retention policy or change it:

**Keep forever (cold storage after 7 days):**
```bash
curl -X PUT "http://localhost:9200/_ilm/policy/pfelk-forever?pretty" \
    -H 'Content-Type: application/json' -d '
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "1d",
        "actions": {
          "set_priority": { "priority": 50 },
          "forcemerge": { "max_num_segments": 1 },
          "readonly": {}
        }
      },
      "cold": {
        "min_age": "7d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      }
    }
  }
}'
```

**Delete after 7 days:**
```bash
curl -X PUT "http://localhost:9200/_ilm/policy/pfelk-7days?pretty" \
    -H 'Content-Type: application/json' -d '
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "1d",
        "actions": {
          "set_priority": { "priority": 50 },
          "forcemerge": { "max_num_segments": 1 },
          "readonly": {}
        }
      },
      "delete": {
        "min_age": "7d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

### 5. Index Template

Replace `POLICY_NAME` with your chosen policy (`pfelk-forever` or `pfelk-7days`):

```bash
curl -X PUT "http://localhost:9200/_index_template/pfelg" -H 'Content-Type: application/json' -d '
{
  "index_patterns": ["pfelk-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "30s",
        "codec": "best_compression",
        "lifecycle": { "name": "POLICY_NAME" },
        "mapping": { "total_fields": { "limit": "10000" } }
      }
    },
    "mappings": {
      "dynamic_templates": [
        { "strings_as_keyword": { "match_mapping_type": "string", "mapping": { "type": "keyword", "ignore_above": 1024 } } }
      ],
      "date_detection": false,
      "properties": {
        "@timestamp": { "type": "date" },
        "source": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "long" },
            "geo": {
              "properties": {
                "city_name": { "type": "keyword" },
                "country_iso_code": { "type": "keyword" },
                "country_name": { "type": "keyword" },
                "location": { "type": "geo_point" }
              }
            },
            "as": { "properties": { "number": { "type": "long" }, "organization": { "properties": { "name": { "type": "keyword" } } } } }
          }
        },
        "destination": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "long" },
            "geo": {
              "properties": {
                "city_name": { "type": "keyword" },
                "country_iso_code": { "type": "keyword" },
                "country_name": { "type": "keyword" },
                "location": { "type": "geo_point" }
              }
            },
            "as": { "properties": { "number": { "type": "long" }, "organization": { "properties": { "name": { "type": "keyword" } } } } }
          }
        },
        "network": { "properties": { "direction": { "type": "keyword" }, "type": { "type": "keyword" }, "transport": { "type": "keyword" } } },
        "event": { "properties": { "action": { "type": "keyword" }, "reason": { "type": "keyword" } } },
        "rule": { "properties": { "id": { "type": "keyword" } } },
        "interface": { "properties": { "name": { "type": "keyword" } } },
        "tags": { "type": "keyword" }
      }
    }
  }
}'
```

### 6. OPNsense Configuration

**System → Settings → Logging / targets → Add:**

| Setting | Value |
|---------|-------|
| Transport | UDP(4) |
| Applications | filter (filterlog) |
| Hostname | Your Docker host IP |
| Port | 5140 |
| **RFC5424** | **✅ MUST be enabled** |

> ⚠️ Without RFC5424, timestamps will be missing timezone info and data will appear with incorrect times in Grafana.

### 7. Grafana Data Source

| Setting | Value |
|---------|-------|
| Type | Elasticsearch |
| URL | `http://YOUR_HOST:9200` |
| Index name | `pfelk-*` |
| Time field | `@timestamp` |
| Version | 8.0+ |

## Available Fields

| Field | Description |
|-------|-------------|
| `event.action` | pass / block |
| `source.ip` / `destination.ip` | IP addresses |
| `source.port` / `destination.port` | Ports |
| `source.geo.location` / `destination.geo.location` | Coordinates (for maps) |
| `source.geo.country_name` / `destination.geo.country_name` | Country names |
| `network.transport` | tcp / udp / icmp |
| `interface.name` | wan / lan / etc. |
| `rule.id` | Firewall rule ID |

## Query Examples

```
event.action:block
event.action:block AND destination.port:443
event.action:pass AND destination.port:22
source.geo.country_name:Germany
```

## Useful Commands

```bash
# List indices
curl -s "http://localhost:9200/_cat/indices/pfelk-*?v&h=index,docs.count,store.size"

# Check ILM status
curl -s "http://localhost:9200/pfelk-*/_ilm/explain?pretty" | grep -E "(index|phase)"

# Delete all indices
for i in $(curl -s "http://localhost:9200/_cat/indices/pfelk-*?h=index"); do curl -X DELETE "http://localhost:9200/$i"; done

# Logstash logs
docker logs pfelg-logstash --tail 50
```

## Troubleshooting

**No data in Grafana:** Check if indices exist (`curl localhost:9200/_cat/indices/pfelk-*`), verify Logstash logs, expand time range.

**Fields have .keyword suffix:** Reinstall template, delete existing indices, restart Logstash.

**GeoIP not working:** Verify MaxMind files exist in mounted directory.

**Wrong timestamps:** Enable RFC5424 in OPNsense logging settings.

## RAM Usage

| Heap | Total RAM |
|------|-----------|
| ES: 256 MB / LS: 256 MB | ~1.5 GB |
| ES: 512 MB / LS: 512 MB | ~2.5 GB |

## Unraid User Scripts

Manual cleanup scripts for Unraid. Add via **Settings → User Scripts → Add New Script**.

### Delete indices older than X days

```bash
#!/bin/bash
# CONFIGURATION - adjust as needed:
DAYS_TO_KEEP=30

ES_HOST="http://localhost:9200"

echo "Deleting indices older than ${DAYS_TO_KEEP} days..."

for INDEX in $(curl -s "${ES_HOST}/_cat/indices/pfelk-*?h=index" 2>/dev/null); do
    INDEX_DATE=$(echo "$INDEX" | grep -oE '[0-9]{4}\.[0-9]{2}\.[0-9]{2}$')
    
    if [ -z "$INDEX_DATE" ]; then
        continue
    fi
    
    INDEX_EPOCH=$(date -d "${INDEX_DATE//./-}" +%s 2>/dev/null)
    CUTOFF_EPOCH=$(date -d "${DAYS_TO_KEEP} days ago" +%s)
    
    if [ "$INDEX_EPOCH" -lt "$CUTOFF_EPOCH" ]; then
        echo "Deleting: $INDEX"
        curl -s -X DELETE "${ES_HOST}/${INDEX}"
    fi
done

echo ""
echo "Remaining indices:"
curl -s "${ES_HOST}/_cat/indices/pfelk-*?v&h=index,docs.count,store.size"
```

### Delete all indices

```bash
#!/bin/bash
ES_HOST="http://localhost:9200"

echo "Deleting ALL pfelk indices..."

for INDEX in $(curl -s "${ES_HOST}/_cat/indices/pfelk-*?h=index" 2>/dev/null); do
    echo "Deleting: $INDEX"
    curl -s -X DELETE "${ES_HOST}/${INDEX}"
done

echo "Done!"
```

## 🙏 Credits

Based on [pfELK Project](https://github.com/pfelk/pfelk) by pfelk.

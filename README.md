# Elasticsearch MCP Server

This repository contains experimental features intended for research and evaluation and are not production-ready.

Connect to your Elasticsearch data directly from any MCP Client (like Claude Desktop) using the Model Context Protocol (MCP).

This server connects agents to your Elasticsearch data using the Model Context Protocol. It allows you to interact with your Elasticsearch indices through natural language conversations.

<a href="https://glama.ai/mcp/servers/@elastic/mcp-server-elasticsearch">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@elastic/mcp-server-elasticsearch/badge" alt="Elasticsearch Server MCP server" />
</a>

## Available Tools

* `list_indices`: List all available Elasticsearch indices
* `get_mappings`: Get field mappings for a specific Elasticsearch index
* `search`: Perform an Elasticsearch search with the provided query DSL
* `get_shards`: Get shard information for all or specific indices
* `create_index`: Create a new Elasticsearch index with optional mappings and settings
* `ingest_document`: Insert a document into an Elasticsearch index
* `bulk_ingest`: Insert multiple documents into an Elasticsearch index in a single request
* `create_alert`: Create an Elasticsearch watcher alert based on query conditions
* `get_alerts`: List all existing alerts (watches) in Elasticsearch
* `delete_alert`: Delete an existing alert (watch) in Elasticsearch
* `build_query`: Build an Elasticsearch query without writing raw JSON
* `field_analytics`: Get statistical insights about fields in an Elasticsearch index
* `generate_security_logs`: Generate realistic security logs in ECS format for security testing and analysis
* `lookup_ioc`: Check indicators of compromise against threat intelligence sources

## Prerequisites

* An Elasticsearch instance
* Elasticsearch authentication credentials (API key or username/password)
* MCP Client (e.g. Claude Desktop)

## Query Capabilities Guide

The Elasticsearch MCP Server supports a variety of query patterns and use cases. Here's a guide to the different types of queries you can perform:

### Basic Queries

* **Index Management**
  - List all indices: `list_indices`
  - Get index mappings: `get_mappings`
  - Get shard information: `get_shards`
  - Create a new index: `create_index`

* **Document Operations**
  - Insert single document: `ingest_document`
  - Bulk insert multiple documents: `bulk_ingest`

* **Search Operations**
  - Full query DSL search: `search`
  - Simplified query building: `build_query`

### Advanced Queries

* **Analytics Queries**
  - Statistical analysis of fields: `field_analytics` with type "stats"
  - Cardinality (unique values): `field_analytics` with type "cardinality"
  - Percentile distributions: `field_analytics` with type "percentiles"
  - Histogram generation: `field_analytics` with type "histogram"
  - Term frequency analysis: `field_analytics` with type "terms"
  - Date histogram analysis: `field_analytics` with type "date_histogram"

* **Security Features**
  - Alert creation and management: `create_alert`, `get_alerts`, `delete_alert`
  - Security log generation: `generate_security_logs` with various event types
  - Threat intelligence lookups: `lookup_ioc` for hashes, IPs, domains, URLs

### Query Types Supported

* **Term Queries**: Exact value matches
* **Match Queries**: Text-based searches with analyzer support
* **Range Queries**: Numerical or date range filtering
* **Existence Queries**: Check if a field exists
* **Wildcard Queries**: Pattern matching with wildcards
* **Multi-field Queries**: Search across multiple fields
* **Boolean Queries**: Combine multiple query conditions with AND/OR logic

### Query Parameters

Queries can be customized with additional parameters like:
* Pagination (`from` and `size`)
* Sorting options (field and direction)
* Field filtering (include/exclude fields)
* Highlighting of matching terms
* Aggregation functions

## Example Workflow: Security Log Analysis

This workflow demonstrates a typical security analysis process using the Elasticsearch MCP server, from data generation to threat detection.

### Step 1: Create a Security Index

First, let's create an index specifically designed for security logs:

```
Create a new index called "security-events" with the following settings:
{
  "number_of_shards": 1,
  "number_of_replicas": 0
}
and mappings for Elastic Common Schema (ECS) fields.
```

### Step 2: Generate and Ingest Security Logs

Now, let's generate some security logs to analyze:

```
Generate 100 authentication events with 30% failure rate and store them in the "security-events" index
```

```
Generate 50 network traffic events and store them in the security-events index
```

```
Generate 25 intrusion detection events from the past week and store them in the security-events index
```

### Step 3: Perform Basic Analysis

Let's check what we have in our index:

```
Get mappings for the security-events index
```

Now, let's search for failed authentication attempts:

```
Build a query for the security-events index with:
- queryType: bool
- boolClauses: {
    "must": [
      {"term": {"event.category": "authentication"}},
      {"term": {"event.outcome": "failure"}}
    ]
  }
- size: 10
```

### Step 4: Advanced Analytics

Now let's perform some statistical analysis:

```
Run field analytics on the security-events index for field "source.ip" with analyticType "cardinality"
```

```
Run field analytics on the security-events index for field "event.outcome" with analyticType "terms"
```

### Step 5: Identify Potential Threats

Let's look for patterns that might indicate an attack:

```
Search the security-events index with the following query:
{
  "bool": {
    "must": [
      {"term": {"event.category": "authentication"}},
      {"term": {"event.outcome": "failure"}}
    ],
    "should": [
      {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}}
    ],
    "minimum_should_match": 1
  }
}
```

### Step 6: Investigate Suspicious IPs

For any suspicious IPs found, we can check against threat intelligence:

```
Lookup the IP 203.0.113.1 using the lookup_ioc tool to check if it's associated with known threats
```

### Step 7: Set Up Alerting

Finally, let's create an alert to notify us of future suspicious activity:

```
Create an alert called "Multiple Auth Failures" to monitor the security-events index
for multiple authentication failures from the same IP using the query:
{
  "bool": {
    "must": [
      {"term": {"event.category": "authentication"}},
      {"term": {"event.outcome": "failure"}}
    ]
  }
}
Check every 5 minutes with a schedule of "0 */5 * * * ?" and log the alert to Elasticsearch
```

### Conclusion

This workflow demonstrates how to:
1. Create an index with proper security mappings
2. Generate realistic security logs for testing
3. Perform basic and advanced searches
4. Analyze patterns in the data
5. Check suspicious indicators against threat intelligence
6. Set up automated alerting for ongoing monitoring

By combining these capabilities, you can build powerful security monitoring and analysis workflows directly through conversational interactions with your MCP Client.

## Example Questions

> [!TIP]
> Here are some natural language queries you can try with your MCP Client.

* "What indices do I have in my Elasticsearch cluster?"
* "Show me the field mappings for the 'products' index."
* "Find all orders over $500 from last month."
* "Which products received the most 5-star reviews?"
* "Create a new index called 'customers' with appropriate mappings for customer data."
* "Insert this customer record into the customers index."
* "Import these product records into the product catalog."
* "Create an alert that notifies me when there are more than 5 errors in the logs."
* "Show me all the current alerts configured in the system."
* "Delete the alert for low inventory notifications."
* "Help me build a query to find products in a specific price range."
* "What's the distribution of prices in the products index?"
* "Show me the most common categories in the catalog."
* "Generate 100 authentication log entries for testing my security dashboard."
* "Create realistic network traffic logs and store them in the 'network-events' index."
* "Generate sample intrusion detection events from last week for testing."
* "Check if this IP address 8.8.8.8 is associated with any threats."
* "Lookup the hash 44d88612fea8a8f36de82e1278abb02f in VirusTotal."
* "Is domain malware-test.com flagged as malicious in any threat intelligence sources?"

## How It Works

1. The MCP Client analyzes your request and determines which Elasticsearch operations are needed.
2. The MCP server carries out these operations (listing indices, fetching mappings, performing searches).
3. The MCP Client processes the results and presents them in a user-friendly format.

## Alert System

The MCP server supports creating and managing Elasticsearch alerts through the Watcher API:

* **Creating Alerts**: Set up alerts to monitor your data and get notified when specific conditions are met
* **Alert Actions**: Configure different actions when alerts trigger:
  * Log to Elasticsearch logs
  * Store in a dedicated alerts index
  * Send email notifications
  * Call webhooks

### Alert Example

To create a price change alert:

```
Create an alert called "Price Change Alert" to monitor the products index
for items with price changes over 20% using the query:
{
  "bool": {
    "must": [
      { "range": { "price_change_percent": { "gt": 20 } } }
    ]
  }
}

Check every hour with a schedule of "0 0 */1 * * ?"
and send an email notification to "alerts@mycompany.com"
```

## Query Builder

The MCP server includes a query builder tool that helps construct Elasticsearch queries without needing to write raw JSON:

* Supports common query types: term, match, range, exists, wildcard, multi_match, and bool queries
* Includes options for pagination and sorting
* Validates input parameters based on query type
* Returns a structured query that can be used with the search tool

### Query Builder Example

To build a range query for products within a price range:

```
Build a query for the products index to find items with price between 50 and 100 dollars
using a range query on the price field with operators gte and lte.
```

## Field Analytics

The field analytics tool provides statistical insights about fields in your indices:

* **Stats**: Get min, max, avg, sum and count for numeric fields
* **Cardinality**: Count unique values in a field
* **Percentiles**: See value distribution across percentiles
* **Histogram**: Generate numeric range distributions
* **Terms**: Find most common values and their frequencies
* **Date Histogram**: Group date fields into intervals

### Field Analytics Example

To analyze price distribution in a product catalog:

```
Get stats analytics for the price field in the products index
```

To see the most common product categories:

```
Run terms analytics on the category field in the products index with a size of 20
```

## Security Best Practices

> [!WARNING]
> Avoid using cluster-admin privileges. Create dedicated API keys with limited scope and apply fine-grained access control at the index level to prevent unauthorized data access.

You can create a dedicated Elasticsearch API key with minimal permissions to control access to your data:

```
POST /_security/api_key
{
  "name": "es-mcp-server-access",
  "role_descriptors": {
    "mcp_server_role": {
      "cluster": [
        "monitor"
      ],
      "indices": [
        {
          "names": [
            "index-1",
            "index-2",
            "index-pattern-*"
          ],
          "privileges": [
            "read",
            "view_index_metadata"
          ]
        }
      ]
    }
  }
}
```

## Security Log Generator

The MCP server includes a powerful security log generator that creates realistic security events in Elastic Common Schema (ECS) format. This is perfect for:

* Testing Kibana security dashboards and SIEM functionality
* Developing and testing security detection rules
* Training on security monitoring and analysis
* Benchmarking and load testing Elasticsearch with security data

### Supported Event Types

The generator supports 9 different types of security events:

* **Authentication**: Login attempts, auth failures, access control
* **Network Traffic**: Connection details, protocols, bytes transferred
* **Firewall**: Allow/deny events, rule matches, network boundaries
* **File Access**: File operations, sensitive file access
* **Process**: Process execution, command lines, parent/child relationships
* **Intrusion Detection**: IDS/IPS alerts, attack signatures
* **DNS**: Domain name queries and responses
* **TLS**: Secure connection details, certificate information
* **HTTP**: Web traffic, request/response details

### Security Log Generator Examples

Generate authentication logs for testing:

```
Generate 50 authentication events with 30% failure rate and store them in the "auth-logs" index
```

Create a week's worth of intrusion detection alerts:

```
Generate 100 intrusion detection events from the past week and store them in the "security-alerts" index
```

Generate HTTP traffic for specific testing:

```
Generate 200 HTTP events with source IPs from the internal network range and destination IPs from public ranges
```

## Threat Intelligence Integration

The MCP server includes a threat intelligence lookup tool that can check indicators of compromise (IoCs) against multiple threat intelligence sources:

* Check file hashes (MD5, SHA-1, SHA-256) for known malware
* Verify IP addresses for reputation and known malicious activity
* Investigate domains and URLs for potential threats
* Access multiple threat intelligence sources in one query

### Supported Sources

* **VirusTotal**: Aggregated results from 60+ antivirus engines
* **AlienVault OTX**: Open Threat Exchange for community-driven threat data

### Threat Intelligence Examples

Check a file hash:

```
Lookup the hash 44d88612fea8a8f36de82e1278abb02f to check if it's malicious
```

Investigate a suspicious IP:

```
Is the IP address 185.143.223.24 known to be malicious?
```

Verify a domain:

```
Check if phishing-site.example.com is in any threat intelligence feeds
```

### Configuration

To use threat intelligence features, you'll need to set API keys as environment variables:

```
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ALIENVAULT_API_KEY=your_alientvault_api_key
```

## License

This project is licensed under the Apache License 2.0.

## Troubleshooting

* Ensure your MCP configuration is correct.
* Verify that your Elasticsearch URL is accessible from your machine.
* Check that your authentication credentials (API key or username/password) have the necessary permissions.
* If using SSL/TLS with a custom CA, verify that the certificate path is correct and the file is readable.
* Look at the terminal output for error messages.

If you encounter issues, feel free to open an issue on the GitHub repository.

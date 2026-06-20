---
name: search_docs
description: >
  Search the project's internal documentation and return the top matching
  passages with their source file paths. Read-only; never modifies files.
  Use this to answer questions about how the codebase or product works.
when_to_use: When the user asks how the codebase or product works.
allowed-tools: Read(docs/**)
input_schema:
  type: object
  properties:
    query:
      type: string
      description: Natural-language search query.
    max_results:
      type: integer
      minimum: 1
      maximum: 20
      description: Maximum number of passages to return (default 5).
  required: [query]
  additionalProperties: false
scopes:
  - docs:read
---

# search_docs

Returns ranked documentation snippets from the indexed `docs/` directory.
The tool is side-effect free: it only reads indexed documentation and exposes
no parameters beyond the search query and a result limit, so what the user
sees in the approval dialog matches exactly what the tool does.

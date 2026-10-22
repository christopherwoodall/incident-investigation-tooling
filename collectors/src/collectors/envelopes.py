

def resolve_input_envelope(
    cli_queries: list[str] | None,
    use_stdin: bool,
    ctx: dict[str, Any],
) -> dict[str, list[str]]:
    """Build Input Envelope from CLI, stdin, or config.yaml."""
    queries: list[str] = []

    # 1. Stdin (if --stdin passed or data is piped in)
    if use_stdin or (not sys.stdin.isatty() and not cli_queries):
        raw_stdin = sys.stdin.read().strip()
        if raw_stdin:
            if raw_stdin.startswith("{"):
                parsed = json.loads(raw_stdin)
                queries.extend(
                    str(q)
                    for q in (parsed.get("queries") or [])
                    if str(q).strip()
                )
            else:
                queries.extend(
                    line.strip()
                    for line in raw_stdin.splitlines()
                    if line.strip()
                )

    # 2. CLI -q / --query flags
    if cli_queries:
        queries.extend(
            str(q).strip()
            for q in cli_queries
            if str(q).strip()
        )

    # 3. Config fallback
    if not queries:
        yaml_queries = ctx.get("queries") or []
        queries.extend(
            str(q).strip()
            for q in yaml_queries
            if str(q).strip()
        )

    # 4. Allow query-less operations when configured
    if not queries and not ctx.get("queries_optional", False):
        source = ctx["source"]
        op = ctx["operation"]
        raise SystemExit(
            f"Error: No queries provided for '{source} {op}'.\n"
            f"Why: 'surfaces.{source}.{op}.queries' is missing or empty, "
            "and no queries were passed on the CLI.\n"
            f"Fix: Pass `-q <query>`, pipe queries via stdin, or set "
            f"`surfaces.{source}.{op}.queries_optional: true` "
            "if this operation supports query-less collection."
        )

    return {"queries": queries}

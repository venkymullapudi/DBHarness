"""Natural-language input — talk to the database in English, not SQL.

This is the input adapter that lets an agent (or a person) say "show me the open
tickets" instead of writing SQL. It is deliberately thin and, above all, it is
**not trusted**:

    natural language --[Translator]--> structured request / SQL --[the Gate]--> DB

The translator turns words into a *candidate* query, but that candidate is then
run through the exact same deterministic gate pipeline as any other request
(policy → rewrite → approval → audit). So a mistranslation, or a prompt-injected
instruction hidden in the text, can never exceed the principal's grant — at
worst it does an authorized-but-wrong thing, which is why **writes are previewed,
not executed**, until explicitly confirmed.

Two translators ship:

* :class:`RuleBasedTranslator` — deterministic, offline, no API key. Handles the
  common read/count/insert/update/delete phrasings. Great for tests and simple
  asks; raises :class:`NLError` when it can't be sure (fail closed — never guess
  a destructive write).
* :class:`LLMTranslator` — optional, uses an LLM for general phrasing. Its output
  is still only a candidate the gate governs.

The grammar the translator targets is the structured query-builder vocabulary
(:mod:`dbharness.querybuilder`), so everything funnels through one safe path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore


class NLError(ValueError):
    """Raised when natural language cannot be safely interpreted."""


@dataclass
class NLRequest:
    """A candidate query produced from natural language.

    Either a structured op (``op`` + ``kwargs``, compiled by the query builder)
    or raw ``sql`` with its ``mode``. ``interpreted`` is a plain-English echo of
    what the translator understood, always shown back to the caller.
    """

    kind: str  # "structured" | "sql"
    interpreted: str
    op: Optional[str] = None
    kwargs: Dict[str, Any] = field(default_factory=dict)
    sql: Optional[str] = None
    mode: str = "read"  # "read" | "write"


class Translator(Protocol):
    def translate(self, text: str, *, schema: Dict[str, List[str]],
                  context: Dict[str, str]) -> NLRequest: ...


# ---------------------------------------------------------------------------
# Rule-based translator (deterministic, offline)
# ---------------------------------------------------------------------------

_READ_VERBS = r"(?:show|list|get|find|display|give me|fetch|select|what are|which)"
_COUNT_VERBS = r"(?:how many|count(?: of)?|number of)"
_INSERT_VERBS = r"(?:add|create|insert|new)"
_UPDATE_VERBS = r"(?:update|set|change|modify)"
_DELETE_VERBS = r"(?:delete|remove|drop row[s]? from|purge)"

# Operator words/symbols -> structured op name.
_COND_OPS = [
    (r"(?:>=|is at least|at least|no less than)", "gte"),
    (r"(?:<=|is at most|at most|no more than)", "lte"),
    (r"(?:!=|<>|is not|isn't|not equal to)", "ne"),
    (r"(?:>|greater than|more than|above|over)", "gt"),
    (r"(?:<|less than|below|under)", "lt"),
    (r"(?:contains|containing|like|matching)", "like"),
    (r"(?:=|==|is|equals|equal to|of)", "eq"),
]

_LIMIT_RE = re.compile(r"\b(?:limit|top|first)\s+(\d+)\b", re.I)
_VALUE_RE = r"(?:'([^']*)'|\"([^\"]*)\"|([-\w.@%]+))"


def _norm(s: str) -> str:
    return re.sub(r"[\s_]+", "", s.lower())


class RuleBasedTranslator:
    """Translate a useful subset of English to structured requests, deterministically."""

    def translate(self, text: str, *, schema: Dict[str, List[str]],
                  context: Dict[str, str]) -> NLRequest:
        if not text or not text.strip():
            raise NLError("empty request")
        t = " ".join(text.strip().split())
        low = t.lower()

        table, table_cols = self._resolve_table(low, schema)

        if re.match(rf"^\s*{_DELETE_VERBS}\b", low):
            return self._delete(t, low, table, table_cols)
        if re.match(rf"^\s*{_UPDATE_VERBS}\b", low):
            return self._update(t, low, table, table_cols)
        if re.match(rf"^\s*{_INSERT_VERBS}\b", low):
            return self._insert(t, low, table, table_cols)
        if re.match(rf"^\s*{_COUNT_VERBS}\b", low):
            return self._count(t, low, table, table_cols)
        if re.match(rf"^\s*{_READ_VERBS}\b", low):
            return self._find(t, low, table, table_cols)

        raise NLError(
            "could not understand the request; start with show/list/count/add/"
            "update/delete, or use the structured tools")

    # -- table / column resolution -------------------------------------------

    def _resolve_table(self, low: str, schema: Dict[str, List[str]]):
        # Map normalized bare table name (and a naive singular/plural) -> real name.
        candidates: Dict[str, str] = {}
        for full in schema:
            bare = full.split(".")[-1]
            candidates[_norm(bare)] = full
            candidates[_norm(bare).rstrip("s")] = full  # singular-ish
        # longest names first so "ticket_comments" wins over "tickets".
        for key in sorted(candidates, key=len, reverse=True):
            if key and key in _norm(low):
                full = candidates[key]
                return full, [c.lower() for c in schema[full]]
        raise NLError(
            "could not tell which table you mean; known tables: "
            + ", ".join(sorted(t.split('.')[-1] for t in schema)))

    def _known_col(self, name: str, cols: List[str]) -> Optional[str]:
        n = _norm(name)
        for c in cols:
            if _norm(c) == n:
                return c
        return None

    # -- conditions ----------------------------------------------------------

    def _parse_conditions(self, segment: str, cols: List[str]) -> List[Dict[str, Any]]:
        """Parse 'col is x and col2 > y' into structured filters."""
        if not segment or not segment.strip():
            return []
        filters: List[Dict[str, Any]] = []
        for part in re.split(r"\s+and\s+", segment.strip(), flags=re.I):
            part = part.strip().rstrip(".")
            if not part:
                continue
            matched = False
            for op_re, op in _COND_OPS:
                m = re.match(rf"^(?P<col>[\w.]+)\s+{op_re}\s+{_VALUE_RE}$", part, re.I)
                if m:
                    col = self._known_col(m.group("col"), cols)
                    if not col:
                        break
                    raw = next(g for g in m.groups()[1:] if g is not None)
                    val = self._coerce(raw)
                    if op == "like" and isinstance(val, str) and "%" not in val:
                        val = f"%{val}%"
                    filters.append({"column": col, "op": op, "value": val})
                    matched = True
                    break
            if not matched:
                raise NLError(f"could not parse condition: {part!r}")
        return filters

    @staticmethod
    def _coerce(raw: str) -> Any:
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        if re.fullmatch(r"-?\d+\.\d+", raw):
            return float(raw)
        if raw.lower() in ("true", "false"):
            return raw.lower() == "true"
        return raw

    def _split_where(self, low: str):
        """Return (before, conditions_text) splitting on the first ' where '/' with '."""
        m = re.search(r"\s+(?:where|with|whose|having|for which)\s+", low, re.I)
        if not m:
            return low, ""
        return low[:m.start()], low[m.end():]

    def _id_filter(self, low: str, table: str, cols: List[str]) -> List[Dict[str, Any]]:
        """Resolve a trailing "<thing> N" (e.g. "ticket 1", "customer #3") to id=N.

        A natural way to name a single row — "close ticket 1", "show customer 3" —
        when the table has an ``id`` column. The number must follow the table word
        (so "top 5 tickets" stays a limit, not an id)."""
        if "id" not in cols:
            return []
        leaf = table.split(".")[-1].lower()
        singular = leaf[:-1] if leaf.endswith("s") else leaf
        m = re.search(rf"\b(?:{re.escape(leaf)}|{re.escape(singular)})\s+#?(\d+)\b", low)
        if m:
            return [{"column": "id", "op": "eq", "value": int(m.group(1))}]
        return []

    # -- builders ------------------------------------------------------------

    def _find(self, t: str, low: str, table: str, cols: List[str]) -> NLRequest:
        before, cond = self._split_where(low)
        # A trailing "limit/top/first N" can land inside the condition segment;
        # pull it out before parsing conditions (it's captured as limit below).
        cond = re.sub(r"\b(?:limit|top|first)\s+\d+\b", " ", cond, flags=re.I).strip()
        filters = self._parse_conditions(cond, cols)
        if not filters:
            filters = self._id_filter(low, table, cols)
        columns = self._wanted_columns(before, table, cols)
        explicit = bool(columns)
        # Default to the principal's *allowed* columns rather than SELECT *, which
        # the gate blocks on any table that has a redacted column. `cols` is
        # already scoped to what this principal may read.
        if not columns:
            columns = list(cols)
        kwargs: Dict[str, Any] = {"table": table, "columns": columns}
        if filters:
            kwargs["filters"] = filters
        limit = _LIMIT_RE.search(low)
        if limit:
            kwargs["limit"] = int(limit.group(1))
        return NLRequest(kind="structured", op="find", kwargs=kwargs, mode="read",
                         interpreted=self._describe("find", table, filters,
                                                    columns if explicit else None,
                                                    kwargs.get("limit")))

    def _count(self, t: str, low: str, table: str, cols: List[str]) -> NLRequest:
        _, cond = self._split_where(low)
        filters = self._parse_conditions(cond, cols)
        # count isn't in the structured vocabulary, so emit SQL (still gated).
        where = ""
        if filters:
            parts = [self._cond_sql(f) for f in filters]
            where = " WHERE " + " AND ".join(parts)
        bare = table.split(".")[-1]
        sql = f"SELECT COUNT(*) AS count FROM {bare}{where}"
        return NLRequest(kind="sql", sql=sql, mode="read",
                         interpreted=f"count rows in {bare}" +
                         (f" where {', '.join(f['column']+' '+f['op']+' '+str(f['value']) for f in filters)}" if filters else ""))

    def _insert(self, t: str, low: str, table: str, cols: List[str]) -> NLRequest:
        m = re.search(r"\bwith\s+(.*)$", low, re.I)
        if not m:
            raise NLError("to add a row, say e.g. 'add a ticket with subject \"x\" priority high'")
        values = self._parse_assignments(m.group(1), cols)
        if not values:
            raise NLError("no recognizable fields to insert")
        return NLRequest(kind="structured", op="insert",
                         kwargs={"table": table, "values": values}, mode="write",
                         interpreted=f"insert into {table.split('.')[-1]}: " +
                         ", ".join(f"{k}={v!r}" for k, v in values.items()))

    def _update(self, t: str, low: str, table: str, cols: List[str]) -> NLRequest:
        leaf_raw = table.split(".")[-1].lower()
        singular = leaf_raw[:-1] if leaf_raw.endswith("s") else leaf_raw
        before, cond = self._split_where(low)
        filters = self._parse_conditions(cond, cols)
        if not filters:
            filters = self._id_filter(low, table, cols)
            if filters:  # drop the matched "<table> N" phrase from the assignment text
                before = re.sub(rf"\b(?:{re.escape(leaf_raw)}|{re.escape(singular)})\s+#?\d+\b",
                                " ", before, flags=re.I)
        # assignment segment is between the table and the where-clause. Strip the
        # leading verb, a "<prep> <table>" phrase ("set ... on tickets"), any
        # remaining bare table mention, a leading "set", and a dangling preposition.
        leaf = re.escape(leaf_raw)
        seg = re.sub(rf"^.*?{_UPDATE_VERBS}\b", "", before, flags=re.I)
        seg = re.sub(rf"\b(?:on|in|for|of|from)\s+{leaf}s?\b", " ", seg, flags=re.I)
        seg = re.sub(rf"\b{leaf}s?\b", " ", seg, flags=re.I)
        seg = re.sub(r"^\s*set\s+", "", seg.strip(), flags=re.I)
        seg = re.sub(r"\b(?:on|in|for|of|from)\b\s*$", "", seg.strip(), flags=re.I).strip()
        values = self._parse_assignments(seg, cols)
        if not values:
            raise NLError("couldn't find what to set; say e.g. 'set status to closed on tickets where id is 1'")
        return NLRequest(kind="structured", op="update",
                         kwargs={"table": table, "values": values,
                                 "filters": filters, "all": not filters},
                         mode="write",
                         interpreted=f"update {table.split('.')[-1]} set " +
                         ", ".join(f"{k}={v!r}" for k, v in values.items()) +
                         (f" where {self._desc_conds(filters)}" if filters else " (ALL rows)"))

    def _delete(self, t: str, low: str, table: str, cols: List[str]) -> NLRequest:
        _, cond = self._split_where(low)
        filters = self._parse_conditions(cond, cols)
        if not filters:
            filters = self._id_filter(low, table, cols)
        return NLRequest(kind="structured", op="delete",
                         kwargs={"table": table, "filters": filters, "all": not filters},
                         mode="write",
                         interpreted=f"delete from {table.split('.')[-1]}" +
                         (f" where {self._desc_conds(filters)}" if filters else " (ALL rows)"))

    # -- helpers -------------------------------------------------------------

    def _wanted_columns(self, before: str, table: str, cols: List[str]) -> Optional[List[str]]:
        """Pull explicit columns from phrasing like 'name and email of customers'."""
        m = re.search(r"(?:show|list|get|find|display|give me|select)\s+(?:me\s+)?(?:the\s+)?(.*?)\s+(?:of|from|in|for)\s+", before, re.I)
        if not m:
            return None
        chunk = m.group(1)
        if re.fullmatch(r"all|everything|\*", chunk.strip(), re.I):
            return None
        wanted = []
        for w in re.split(r"[,]|\sand\s", chunk):
            c = self._known_col(w.strip(), cols)
            if c:
                wanted.append(c)
        return wanted or None

    def _parse_assignments(self, seg: str, cols: List[str]) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for part in re.split(r"[,]|\sand\s", seg):
            part = part.strip().rstrip(".")
            if not part:
                continue
            m = re.match(rf"^(?P<col>[\w.]+)\s*(?:=|:|\bto\b|\bis\b)?\s*{_VALUE_RE}$", part, re.I)
            if not m:
                continue
            col = self._known_col(m.group("col"), cols)
            if not col:
                continue
            raw = next(g for g in m.groups()[1:] if g is not None)
            values[col] = self._coerce(raw)
        return values

    @staticmethod
    def _cond_sql(f: Dict[str, Any]) -> str:
        sym = {"eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=",
               "like": "LIKE"}.get(f["op"], "=")
        v = f["value"]
        lit = str(v) if isinstance(v, (int, float)) else "'" + str(v).replace("'", "''") + "'"
        return f"{f['column']} {sym} {lit}"

    @staticmethod
    def _desc_conds(filters: List[Dict[str, Any]]) -> str:
        return ", ".join(f"{f['column']} {f['op']} {f['value']}" for f in filters)

    def _describe(self, op, table, filters, columns, limit) -> str:
        bare = table.split(".")[-1]
        s = f"find {', '.join(columns) if columns else 'all columns'} in {bare}"
        if filters:
            s += f" where {self._desc_conds(filters)}"
        if limit:
            s += f" (limit {limit})"
        return s


# ---------------------------------------------------------------------------
# LLM translator (optional, general phrasing)
# ---------------------------------------------------------------------------


class LLMTranslator:
    """Translate free-form English via an LLM into a structured request.

    Optional: requires the ``anthropic`` package and ``ANTHROPIC_API_KEY``. The
    LLM only proposes a candidate; the gate still enforces it, so the LLM is
    never trusted with data access. Falls back to ``fallback`` (default: the
    rule-based translator) when unavailable, so callers get a deterministic path.
    """

    _SYSTEM = (
        "You translate a user's request into ONE JSON object describing a database "
        "operation. Output ONLY JSON, no prose. Shape:\n"
        '{"op":"find|insert|update|delete","table":"<table>","columns":[...],'
        '"filters":[{"column":"c","op":"eq|ne|lt|lte|gt|gte|in|like","value":...}],'
        '"values":{"c":v},"limit":N}\n'
        "Use only the tables and columns provided. For writes, include filters. "
        "If the request is unclear or references unknown tables/columns, output "
        '{"error":"reason"}.'
    )

    def __init__(self, model: str = "claude-sonnet-5",
                 fallback: Optional[Translator] = None):
        self.model = model
        self.fallback = fallback or RuleBasedTranslator()

    def translate(self, text: str, *, schema: Dict[str, List[str]],
                  context: Dict[str, str]) -> NLRequest:
        try:
            import json
            import os
            import anthropic
        except ImportError:
            return self.fallback.translate(text, schema=schema, context=context)
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return self.fallback.translate(text, schema=schema, context=context)

        schema_desc = "\n".join(f"- {t}: {', '.join(c)}" for t, c in schema.items())
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=self.model, max_tokens=512, system=self._SYSTEM,
            messages=[{"role": "user",
                       "content": f"Tables:\n{schema_desc}\n\nRequest: {text}"}],
        )
        raw = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
        raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise NLError(f"LLM returned invalid JSON: {exc}") from exc
        if "error" in data:
            raise NLError(str(data["error"]))
        op = data.get("op")
        if op not in ("find", "insert", "update", "delete"):
            raise NLError(f"LLM proposed unknown op {op!r}")
        kwargs = {k: v for k, v in data.items()
                  if k in ("table", "columns", "filters", "values", "limit", "all")}
        mode = "read" if op == "find" else "write"
        return NLRequest(kind="structured", op=op, kwargs=kwargs, mode=mode,
                         interpreted=f"{op} {data.get('table')} (via LLM)")

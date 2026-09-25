"""
analyzers/ast_analyzer.py
Abstract Syntax Tree (AST) analyzer for inspecting Python serverless functions.
Extracts event sources, dangerous sinks, and performs lightweight taint tracking.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Union


@dataclass
class EventSource:
    """Represents an external serverless event input source."""
    variable_name: Optional[str]
    expression_text: str
    line: int
    file: str
    source_key: Optional[str] = None


@dataclass
class SinkCall:
    """Represents a sensitive operation (sink) and its context."""
    sink_name: str
    sink_type: str  # COMMAND, SQL, FILE
    line: int
    file: str
    tainted_args: List[str] = field(default_factory=list)
    is_concatenated: bool = False
    is_fstring: bool = False
    raw_code: str = ""


class ASTCodeAnalyzer(ast.NodeVisitor):
    """
    Parses Python code into an AST and analyzes data flow from serverless
    event sources into potential sinks.
    """

    # Identifiers typically representing external serverless input
    EVENT_OBJECTS = {"event", "request", "body", "params", "query_params"}

    # Known dangerous command execution sinks
    COMMAND_SINKS = {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
    }

    # Known SQL execution sinks
    SQL_SINKS = {"execute", "executemany"}

    # File access sinks
    FILE_SINKS = {"open", "Path.open"}

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)
        self.file_str = str(self.file_path)

        # Discovered event sources
        self.sources: List[EventSource] = []

        # Discovered sink calls
        self.sinks: List[SinkCall] = []

        # Tainted variables mapping: var_name -> source description
        self.tainted_vars: Dict[str, str] = {}

        # Variables holding dynamically concatenated strings: var_name -> list of component var names
        self.concatenated_vars: Dict[str, List[str]] = {}

        # Nodes already registered as sources in assignments
        self._assigned_source_nodes: Set[int] = set()

        # Parsing or syntax error details if any
        self.syntax_error: Optional[str] = None
        self.error_line: Optional[int] = None

    def analyze(self, source_code: Optional[str] = None) -> bool:
        """
        Parse source code into an AST and visit all nodes.
        Returns True if parsed successfully, False if a SyntaxError occurs.
        """
        if source_code is None:
            try:
                with open(self.file_path, "r", encoding="utf-8-sig", errors="replace") as f:
                    source_code = f.read()
            except Exception as e:
                self.syntax_error = f"Could not read file: {e}"
                return False

        try:
            tree = ast.parse(source_code, filename=self.file_str)
        except SyntaxError as e:
            self.syntax_error = f"Invalid Python syntax: {e.msg}"
            self.error_line = e.lineno
            return False

        # Walk the AST nodes in order
        self.visit(tree)
        return True

    def _get_call_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name string from Call.func node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_name = self._get_call_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
            return node.attr
        return None

    def _is_event_source(self, node: ast.AST) -> Optional[str]:
        """
        Check if an AST node is an event access:
        - Subscript: event["username"], request.args["id"]
        - Method call: event.get("username")
        Returns a friendly representation string if it is an event source, else None.
        """
        # Case 1: Subscript (e.g. event["username"])
        if isinstance(node, ast.Subscript):
            base_name = self._get_call_name(node.value)
            if base_name and any(src in base_name.lower() for src in self.EVENT_OBJECTS):
                key = ""
                if isinstance(node.slice, ast.Constant):
                    key = str(node.slice.value)
                return f"{base_name}['{key}']"

        # Case 2: Method call (e.g. event.get("username"))
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            if call_name and any(src in call_name.lower() for src in self.EVENT_OBJECTS):
                if call_name.endswith(".get") and node.args:
                    first_arg = node.args[0]
                    key = first_arg.value if isinstance(first_arg, ast.Constant) else ""
                    return f"{call_name}('{key}')"
                return call_name

        return None

    def _contains_tainted(self, node: ast.AST) -> List[str]:
        """Recursively check if an expression node contains any tainted variable."""
        tainted_found: List[str] = []

        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                tainted_found.append(node.id)

        elif isinstance(node, ast.BinOp):
            tainted_found.extend(self._contains_tainted(node.left))
            tainted_found.extend(self._contains_tainted(node.right))

        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    tainted_found.extend(self._contains_tainted(value.value))

        elif isinstance(node, ast.Call):
            for arg in node.args:
                tainted_found.extend(self._contains_tainted(arg))

        return list(set(tainted_found))

    def _is_string_construction(self, node: ast.AST) -> bool:
        """Check if node constructs strings dynamically (concatenation or f-string)."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        return False

    def visit_Assign(self, node: ast.Assign):
        """Analyze assignments to track taint propagation."""
        # Check if the right-hand value is an event source
        source_repr = self._is_event_source(node.value)

        # Determine target variable names
        target_names: List[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id)

        if source_repr:
            self._assigned_source_nodes.add(id(node.value))
            # Direct assignment from event: username = event["username"]
            for target_name in target_names:
                self.tainted_vars[target_name] = source_repr
                self.sources.append(
                    EventSource(
                        variable_name=target_name,
                        expression_text=source_repr,
                        line=node.lineno,
                        file=self.file_str
                    )
                )
        else:
            # Check if assigned value derives from tainted variables
            tainted_deps = self._contains_tainted(node.value)
            if tainted_deps:
                for target_name in target_names:
                    self.tainted_vars[target_name] = f"Derived from {', '.join(tainted_deps)}"
                    if self._is_string_construction(node.value):
                        self.concatenated_vars[target_name] = tainted_deps

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Analyze function calls for dangerous sinks."""
        call_name = self._get_call_name(node.func)

        # Check if the call itself is an unassigned event source (e.g. print(event.get("x")))
        if id(node) not in self._assigned_source_nodes:
            source_repr = self._is_event_source(node)
            if source_repr:
                self.sources.append(
                    EventSource(
                        variable_name=None,
                        expression_text=source_repr,
                        line=node.lineno,
                        file=self.file_str
                    )
                )

        if not call_name:
            self.generic_visit(node)
            return

        # 1. Command Execution Sinks
        if call_name in self.COMMAND_SINKS:
            tainted_in_args: List[str] = []
            is_concat = False
            is_fstr = False

            for arg in node.args:
                tainted_in_args.extend(self._contains_tainted(arg))
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    is_concat = True
                if isinstance(arg, ast.JoinedStr):
                    is_fstr = True
                if isinstance(arg, ast.Name) and arg.id in self.concatenated_vars:
                    is_concat = True

            if tainted_in_args:
                self.sinks.append(
                    SinkCall(
                        sink_name=call_name,
                        sink_type="COMMAND",
                        line=node.lineno,
                        file=self.file_str,
                        tainted_args=list(set(tainted_in_args)),
                        is_concatenated=is_concat,
                        is_fstring=is_fstr
                    )
                )

        # 2. SQL Execution Sinks: cursor.execute(), connection.execute()
        func_attr = call_name.split(".")[-1]
        if func_attr in self.SQL_SINKS:
            if node.args:
                first_arg = node.args[0]
                tainted_in_query = self._contains_tainted(first_arg)
                is_concat = (
                    (isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add)) or
                    (isinstance(first_arg, ast.Name) and first_arg.id in self.concatenated_vars)
                )
                is_fstr = isinstance(first_arg, ast.JoinedStr)

                # Flag if query contains tainted input via concatenation or f-string
                if tainted_in_query and (is_concat or is_fstr):
                    self.sinks.append(
                        SinkCall(
                            sink_name=call_name,
                            sink_type="SQL",
                            line=node.lineno,
                            file=self.file_str,
                            tainted_args=list(set(tainted_in_query)),
                            is_concatenated=is_concat,
                            is_fstring=is_fstr
                        )
                    )

        # 3. File Access Sinks: open(...)
        if call_name in self.FILE_SINKS or call_name.endswith(".open"):
            if node.args:
                first_arg = node.args[0]
                tainted_in_file = self._contains_tainted(first_arg)
                is_concat = (
                    (isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add)) or
                    (isinstance(first_arg, ast.Name) and first_arg.id in self.concatenated_vars)
                )
                if tainted_in_file:
                    self.sinks.append(
                        SinkCall(
                            sink_name=call_name,
                            sink_type="FILE",
                            line=node.lineno,
                            file=self.file_str,
                            tainted_args=list(set(tainted_in_file)),
                            is_concatenated=is_concat
                        )
                    )

        self.generic_visit(node)

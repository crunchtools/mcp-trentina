/**
 * Trentina's trust boundary, modelled for CodeQL (#269).
 *
 * Sources: the parameters of every `@mcp.tool()` function (the internal tool
 * surface served to agents), the `arguments` the gateway forwards to an
 * internal tool, and the payloads that arrive from outside: `fetch_url`'s
 * result and a backend's `call_backend_tool` result.
 *
 * The tool parameters are also added to `RemoteFlowSource`, so the standard
 * Python security queries (py/full-ssrf, py/path-injection, py/log-injection)
 * see them as well. Before this they did not, which is why
 * `security-extended` missed #260 and #261.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module Trentina {
  /** A function registered as an MCP tool with `@mcp.tool()` or `@mcp.tool`. */
  class McpToolFunction extends Function {
    McpToolFunction() {
      exists(Expr decorator | decorator = this.getADecorator() |
        decorator.(Call).getFunc().(Attribute).getName() = "tool"
        or
        decorator.(Attribute).getName() = "tool"
      )
    }
  }

  /** A call whose callee is named `name`, as a bare name or an attribute. */
  bindingset[name]
  predicate calls(DataFlow::CallCfgNode call, string name) {
    call.getFunction().asExpr().(Name).getId() = name
    or
    call.getFunction().asExpr().(Attribute).getName() = name
  }

  /** A value an agent chose: a tool parameter or the arguments of an internal call. */
  class ToolArgument extends DataFlow::ParameterNode {
    ToolArgument() {
      this.getParameter() = any(McpToolFunction f).getAnArg()
      or
      exists(Function f |
        f.getName() = "call_internal_tool" and
        this.getParameter() = f.getArgByName("arguments")
      )
    }
  }

  /** The tool parameters, as remote input for every query that uses the concept. */
  class ToolArgumentAsRemoteSource extends RemoteFlowSource::Range instanceof ToolArgument {
    override string getSourceType() { result = "MCP tool argument" }
  }

  /** Bytes that arrived from outside the boundary: a fetched page, a backend's result. */
  class UntrustedPayload extends DataFlow::CallCfgNode {
    UntrustedPayload() {
      calls(this, "fetch_url") or
      calls(this, "call_backend_tool")
    }
  }

  /**
   * The egress guard (#260). Its argument is checked on the resolved address
   * and every hop is re-checked, so a URL that reaches it is discharged.
   */
  class EgressBarrier extends DataFlow::Node {
    EgressBarrier() {
      exists(DataFlow::CallCfgNode call |
        calls(call, ["check_url", "open_guarded"]) and
        this = call.getArg(_)
      )
      or
      // Everything inside the guard itself is the guard.
      this.getLocation().getFile().getBaseName() = "egress.py"
    }
  }

  /** The judging layers: content handed to one of these is judged before delivery. */
  class DefendBarrier extends DataFlow::Node {
    DefendBarrier() {
      exists(DataFlow::CallCfgNode call |
        calls(call,
          [
            "defend", "defend_json", "defend_selection", "judge_and_deliver",
            "scan_tool_response"
          ]) and
        (this = call.getArg(_) or this = call.getArgByName(_))
      )
    }
  }

  /** The logging rule's allowed forms (#262): a fingerprint, a kind, a site. */
  class LogsafeBarrier extends DataFlow::Node {
    LogsafeBarrier() {
      exists(DataFlow::CallCfgNode call |
        calls(call,
          ["redact_source", "exc_kind", "exc_where", "safe_path", "safe_address", "loggable_tool"]) and
        this = call
      )
    }
  }

  /** What an `@mcp.tool` function returns: delivered to the agent as the result. */
  class ToolReturn extends DataFlow::Node {
    ToolReturn() {
      exists(Return ret, McpToolFunction f |
        ret.getScope() = f and
        this.asExpr() = ret.getValue()
      )
    }
  }
}

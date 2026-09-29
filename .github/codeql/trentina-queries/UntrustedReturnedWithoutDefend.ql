/**
 * @name Untrusted payload returned from a tool without defend()
 * @description A fetched page or a backend's result reaches an MCP tool's
 *              return value without passing a judging layer (defend,
 *              defend_json, defend_selection, judge_and_deliver,
 *              scan_tool_response). Best effort: the gateway's own tools/call
 *              path scans and then delivers the SAME bytes by design, which
 *              taint tracking cannot tell from a bypass, so only the internal
 *              @mcp.tool surface is checked here.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @id trentina/untrusted-returned-without-defend
 * @tags security
 *       external/cwe/cwe-20
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import TrentinaModel

module UndefendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Trentina::UntrustedPayload }

  predicate isSink(DataFlow::Node node) { node instanceof Trentina::ToolReturn }

  predicate isBarrier(DataFlow::Node node) { node instanceof Trentina::DefendBarrier }
}

module UndefendedFlow = TaintTracking::Global<UndefendedConfig>;

import UndefendedFlow::PathGraph

from UndefendedFlow::PathNode source, UndefendedFlow::PathNode sink
where UndefendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This tool result carries $@ that no layer judged.",
  source.getNode(), "an untrusted payload"

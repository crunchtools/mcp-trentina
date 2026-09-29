/**
 * @name Tool argument reaches an HTTP client without the egress check
 * @description An agent-chosen value becomes part of an outbound request URL
 *              without passing egress.check_url or egress.open_guarded, which
 *              decide on the resolved address and re-check every redirect hop.
 *              That is SSRF into the gateway's own network (#260).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id trentina/tool-arg-to-http-client-without-egress-check
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import TrentinaModel

module EgressConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Trentina::ToolArgument }

  predicate isSink(DataFlow::Node node) {
    exists(Http::Client::Request request | node = request.getAUrlPart())
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof Trentina::EgressBarrier }
}

module EgressFlow = TaintTracking::Global<EgressConfig>;

import EgressFlow::PathGraph

from EgressFlow::PathNode source, EgressFlow::PathNode sink
where EgressFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This request URL depends on $@ and never passes the egress guard.", source.getNode(),
  "an MCP tool argument"

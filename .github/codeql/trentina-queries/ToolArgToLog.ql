/**
 * @name Tool argument written to a log
 * @description The gateway's journal is readable by other agents through
 *              journal and container-log tools, so an agent-chosen string that
 *              reaches a log record is a message board between agents (#262).
 *              Log logsafe.redact_source(value) instead.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @id trentina/tool-arg-to-log
 * @tags security
 *       external/cwe/cwe-117
 *       external/cwe/cwe-532
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import TrentinaModel

module LogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Trentina::ToolArgument }

  predicate isSink(DataFlow::Node node) { node = any(Logging log).getAnInput() }

  predicate isBarrier(DataFlow::Node node) { node instanceof Trentina::LogsafeBarrier }
}

module LogFlow = TaintTracking::Global<LogConfig>;

import LogFlow::PathGraph

from LogFlow::PathNode source, LogFlow::PathNode sink
where LogFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This log record carries $@ verbatim.", source.getNode(),
  "an MCP tool argument"

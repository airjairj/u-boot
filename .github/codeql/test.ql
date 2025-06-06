/**
 * @kind path-problem
 */

 import cpp
 import semmle.code.cpp.dataflow.new.TaintTracking
 
 class NetworkByteSwap extends Expr {
   NetworkByteSwap () {
     exists(MacroInvocation mi |
       mi.getMacroName().regexpMatch("ntoh(l|ll|s)") and
       mi.getExpr() = this
     )
   }
 }
 
 module MyFlowConfiguration implements DataFlow::ConfigSig {
   predicate isSource(DataFlow::Node source) {
     source.asExpr() instanceof NetworkByteSwap
   }
 
   predicate isSink(DataFlow::Node sink) {
     exists(FunctionCall call |
       call.getTarget().hasName("memcpy") and
       call.getArgument(2) = sink.asExpr()
     )
   }

   predicate isBarrier(DataFlow::Node node) {
    exists(BinaryOperation op |
      op.getOperator() in ["<", "<=", ">", ">="] and
      op.getAnOperand() = node.asExpr()
    )
  }
 }
 
module MyTaint = TaintTracking::Global<MyFlowConfiguration>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
 

package com.redhat.certgen
import scala.collection._
import scala.Console.{WHITE, BOLD, BLUE, GREEN, RESET}
trait Node{
  def description: String
  def children: Iterator[Node]
}

trait TreeDrawer{
  def drawTree(node: Node): Unit
}

trait Printer{
  def printExtensions(str: String): Unit = print(str)
  def printNodeDesc(str: String, parent: Boolean): Unit = println(str)
}

class ColorPrinter(val nodeExtensionsColor: String = RESET + WHITE,
		   val parentColor: String = RESET + BOLD + BLUE,
		   val childColor: String = RESET + GREEN) extends Printer{
  override def printExtensions(str: String){
    print(nodeExtensionsColor)
    super.printExtensions(str)
  }

  override def printNodeDesc(str: String, parent: Boolean){
    print(if(parent) parentColor else childColor)
    super.printNodeDesc(str, parent)
  }
}

case class DepthChildState(depth: Int, hasMoreChildren: Boolean)
case class ConsoleOptions(defaultDepth: Int, pipe: String, 
			  extension: String, printer: Printer)
			  
			  
object ConsoleTreeDrawer{
  def drawTree(root: Node){
    val ctd = new ConsoleTreeDrawer
    ctd.drawTree(root)
  }
}
class ConsoleTreeDrawer(options: ConsoleOptions = ConsoleOptions(3, "|", "__", new ColorPrinter))
extends TreeDrawer{
  def drawTree(root: Node){
    def printNode(node: Node, lst: List[DepthChildState]){
      def drawParentPipes(lst: List[DepthChildState]):Unit = lst match {
	case tail::Nil => options.printer.printExtensions(" " * tail.depth 
							  + options.pipe + options.extension)
	case head::tail => 
	  options.printer.printExtensions(" " * head.depth + (if(head.hasMoreChildren) options.pipe else ""))
	  drawParentPipes(tail)
	case _ => println("should not happen")
      }
      drawParentPipes(lst)
      val iter = node.children
      options.printer.printNodeDesc(node.description, iter.hasNext)
      while(iter.hasNext){
	val child = iter.next
	printNode(child, lst :+ DepthChildState(options.defaultDepth, iter.hasNext))
      }
    }
    printNode(root, Nil)
  }
}

object TreeMain extends Application{
  case class CNode(val description: String,
		   val children: List[CNode])
  implicit def cnodeToNode(x: CNode): Node = new Node{
    override def description = x.description
    override def children = x.children.iterator.map(cnodeToNode)
  }
  val test = CNode("txt_12345678900", 
		   List(CNode("node1", 
			      List(CNode("p1",
					 List(CNode("p11", Nil), CNode("p12", Nil))),
				   CNode("p2", Nil))
			      )
			)
		   )
  (new ConsoleTreeDrawer).drawTree(test)

}

/*
txt
 |__node1
    |__ p1
    |	|__ p11
    |	|__ p12
    |__ p2
*/

package com.redhat.certgen
import scala.collection.mutable
import com.redhat.certgen.Utils.implicits._
import com.redhat.certgen.certificate._

object DrawUtils{
  trait ToNode{
    def toNode(all: Boolean = false):Node
    def drawAll = ConsoleTreeDrawer.drawNode(toNode(true))
    def drawExisting = ConsoleTreeDrawer.drawNode(toNode(false))
  }
  object implicits{
    import com.redhat.certgen.{Node, N}
    implicit def gceToNode(gce: GenericCertificateEntity) = new ToNode{
      override def toNode(all: Boolean = false): Node = {
	val fields = if(all) gce.fields else gce.fields.filter(gce \ _ != None)
	N(gce.symbol.name, fields.map {field => gce \ field match{
	  case Some(value) =>  N(field.name + " = " + value)
	  case None => N(field.name)
          }
        }.iterator)
      }
    }
    implicit def certToNode(c: Certificate) = new ToNode{
      import Iterator.{single, empty}
      override def toNode(all: Boolean = false): Node = {
	def optionalComponents:Iterator[Node] = {
	  val bufr = new mutable.ArrayBuffer[Node]
	  def addOpts(opt: Option[GenericCertificateEntity], str: String):Unit = 
	   opt match {
	    case Some(gce) => bufr += N(str, single(gce.toNode(all)))
	    case None => if(all) bufr += N(str)
	   } 
	  def addBufr(b: mutable.Buffer[GenericCertificateEntity], str: String):Unit = {
	    if(b.size == 0 && all) bufr += N(str)
	    else bufr += N(str, b.iterator.map(_.toNode(all)))
	  }

	  addOpts(c.system, "system") 
	  addOpts(c.order, "order")
	  addBufr(c.contents, "contents")
	  addBufr(c.roles, "roles")
	  addBufr(c.products, "products")
	  bufr.iterator
	}
	N("Certificate", List(
	  N("startDate = " + c.startDate),
	  N("endDate = " + c.endDate),
	  N("serial = " + c.serial.toString),
	  N("subjectDN = " + c.subjectDN)
	  ).iterator ++ optionalComponents)
      }
    }
  }
}

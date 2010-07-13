package com.redhat.certgen.editor
import com.redhat.certgen.editor._
import com.github.certgen.annotations._
import scala.collection.mutable
import com.redhat.certgen.certificate.{GenericCertificateEntity, Certificate}
import com.redhat.certgen.Utils.implicits._
import com.redhat.certgen.DrawUtils.implicits._
import com.redhat.certgen.DrawUtils._
import com.redhat.certgen.{Node, N}
import com.redhat.certgen.ConsoleTreeDrawer.drawNode
object GenericCertEntityEditor{
  def apply(obj: AnyRef): GenericCertEntityEditor = {
    val editor = new GenericCertEntityEditor 
    editor.instance = obj
    return editor
  }
}
class GenericCertEntityEditor extends ComplexEditorSupport{

  private def entity = toBeEditedEntity.asInstanceOf[GenericCertificateEntity]
  override def printAll = this.entity.drawAll //printVals(true)
  override def printAvailable = this.entity.drawExisting //printVals(false)
  override def editableFields = Some(entity.fields.map(_.name))
  override def editorFor(property: String) = new SimpleEditor{
    override def apply(str: String) = setValue(Symbol(str), property)
    override def asText = entity \ (Symbol(property)) match{
      case Some(x: String) => x
      case None|_ => ""
    }
    def setValue(sym: Symbol, value: String){
      entity(sym) = value
    }
  }
}
  

 class MultiElementsEditor extends SequenceContainerEditorSupport{
   private def elements = toBeEditedEntity.asInstanceOf[mutable.Buffer[GenericCertificateEntity]]
   override def printAll =
     drawNode(N(category, elements.iterator.map(_.toNode(true))))
   override def printAvailable = drawNode(N(category, 
					    elements.iterator.map(_.toNode(false))))
   override def editableFields = 
     Some(new scala.collection.immutable.Range(0, elements.size, 1).map("" + _))

   override def editorFor(property: String): Editor = {
     if(Integer.parseInt(property) > elements.size){
       println("[Error] Input index exceeds > #" + elements.size)
       return DumbEditor
     }else{
       return GenericCertEntityEditor(elements(property))
     }
   }
   //TODO: Total failure to extract all editor creation to factory. Also role creation does not work
   //Content type always = "yum"
   override def add: Editor = {
     import scala.util.Random._
     import com.redhat.certgen.ExtensionSupport.namespace
     category match {
         case "Content" => 
          val content = GenericCertificateEntity(Symbol("Content"), 
						 namespace.content + "." + nextInt + ".1")
          return addAndReturnEditor(content)
          
        case "Product" =>
          val product = GenericCertificateEntity(Symbol("Product"), 
						 namespace.product + "." + nextInt)
          return addAndReturnEditor(product)
        case _ =>
       }
     DumbEditor
   }
    
   private def addAndReturnEditor(gce: GenericCertificateEntity): Editor = {
     elements += gce
     GenericCertEntityEditor(gce)
   }
 }
 
//not so generic
 class GenericOptionEditor extends OptionEditorSupport{
   override def edit: Editor = {
     import com.redhat.certgen.ExtensionSupport.namespace
     if(!exists){
          category match {
            case "System" =>
              methods.setter.invoke(instance, 
                Some(GenericCertificateEntity(Symbol("System"), namespace.system)))
            case "Order" =>
              methods.setter.invoke(instance,
                Some(GenericCertificateEntity(Symbol("Order"), namespace.order)))
            case _ =>
              return DumbEditor
          }
     }
     GenericCertEntityEditor(toBeEditedEntity)
   }

   private def print(all: Boolean):Unit = drawNode(toBeEditedEntity match {
     case Some(x: GenericCertificateEntity) => N(category, Iterator.single(x.toNode(all)))
     case _ => N(category) //TODO print empty sub fields on None
   })

   override def printAll = print(true)
   override def printAvailable = print(false)
 }

 object CertificateEditor{
   def apply(obj: AnyRef) = {
     val cert = new CertificateEditor
     cert.instance = obj 
     cert
   }
 }
 class CertificateEditor extends ComplexEditorSupport{
   private def cert = instance.asInstanceOf[Certificate]
   override def printAvailable = cert.drawExisting //println(cert.toString)
   override def printAll = cert.drawAll

   private val pds = java.beans.Introspector.getBeanInfo(classOf[Certificate]).getPropertyDescriptors
   private val readMethods = pds.map(_.getReadMethod)
   private val writeMethods = pds.map(_.getWriteMethod).filter(_ != null)

   override val editableFields:Option[IndexedSeq[String]] = Some(readMethods.map(_.getName))
   override def editorFor(property: String): Editor = 
     EditorFactory.editorFor(instance, property)
 }

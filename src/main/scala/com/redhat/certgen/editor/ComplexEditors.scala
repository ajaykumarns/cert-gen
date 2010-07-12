package com.redhat.certgen.editor
import com.redhat.certgen.editor._
import com.github.certgen.annotations._
import scala.collection.mutable
import com.redhat.certgen.CertificateGenerationUtils.{GenericCertificateEntity, Certificate}
import com.redhat.certgen.Utils.implicits._

object GenericCertEntityEditor{
  def apply(obj: AnyRef): GenericCertEntityEditor = {
    val editor = new GenericCertEntityEditor 
    editor.instance = obj
    return editor
  }
}
class GenericCertEntityEditor extends ComplexEditorSupport{
  private def entity = toBeEditedEntity.asInstanceOf[GenericCertificateEntity]
  private def printVals(all: Boolean){
    println(entity.symbol.name)
    for(field <- entity.fields){
      entity \ field match {
        case Some(value) => println(field + "=" + value)
        case None if(all) => println(field + "= [Value not present]")
        case _ =>
      }
    }
  }
  override def printAll = printVals(true)
  override def printAvailable = printVals(false)
  override def editableFields = Some(entity.fields.map(_.name))
  override def editorFor(property: String) = new SimpleEditor{
    override def apply(str: String) = setValue(Symbol(str), property)
    override def asText = entity \ (Symbol(property)) match{
      case Some(x) => x.asInstanceOf[String]
      case None => ""
    }
    def setValue(sym: Symbol, value: String){
      entity(sym) = value
    }
  }
}
  

 class MultiElementsEditor extends SequenceContainerEditorSupport{
   private def elements = toBeEditedEntity.asInstanceOf[mutable.Buffer[GenericCertificateEntity]]
   override def printAll{
     println("\nTotal number of elements: " + elements.size)
     println(elements.mkString("|elements begin|", elements.mkString("\n"), "|elements end|"))
   }

   override def printAvailable = printAll
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
     val ann = getAnn(classOf[CertificateType])
     if(ann != null) {
       ann.asInstanceOf[CertificateType].category match {
         case "Content" => 
          val content = GenericCertificateEntity(Symbol("Content"), namespace.content + "." + nextInt + ".1")
          return addAndReturnEditor(content)
          
        case "Product" =>
          val product = GenericCertificateEntity(Symbol("Product"), namespace.product + "." + nextInt)
          return addAndReturnEditor(product)
        case _ =>
       }
     }
     DumbEditor
   }
    
   private def addAndReturnEditor(gce: GenericCertificateEntity): Editor = {
     elements += gce
     GenericCertEntityEditor(gce)
   }
 }
 
 class GenericOptionEditor extends OptionEditorSupport{
   override def edit: Editor = {
     import com.redhat.certgen.ExtensionSupport.namespace
     if(!exists){
        val ann = getAnn(classOf[CertificateType])
        if(ann != null){
          ann.asInstanceOf[CertificateType].category match {
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
     }
     GenericCertEntityEditor(toBeEditedEntity)
   }
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
   override def printAvailable = println(cert.toString)
   private def printBufr(str: String, iter: mutable.Buffer[GenericCertificateEntity]){
     println("\n|" + (str + "| = " + (if(iter.size > 0) iter.mkString("\n") else "[Value not present]")) )
   }

   override def printAll{
     println("\n|Certificate|\n notBefore = " + cert.startDate + " notAfter = " + cert.endDate)
     println("\nSerial = " + cert.serial)
     println("\nSubjectDN = " + cert.subjectDN)
     printBufr("Contents", cert.contents)
     printBufr("Roles", cert.roles)
     printBufr("Products", cert.products)
     println("\n|System| = " + (if(cert.system != None) cert.system.get.toString else "[Value not present]"))
     println("\n|Order| = " + (if(cert.order != None) cert.order.get.toString else "[Value not present]"))
   }

   private val pds = java.beans.Introspector.getBeanInfo(classOf[Certificate]).getPropertyDescriptors
   private val readMethods = pds.map(_.getReadMethod)
   private val writeMethods = pds.map(_.getWriteMethod).filter(_ != null)

   override val editableFields:Option[IndexedSeq[String]] = Some(readMethods.map(_.getName))
   override def editorFor(property: String): Editor = EditorFactory.editorFor(instance, property)
 }

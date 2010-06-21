package com.redhat.certgen
import com.redhat.certgen.CertificateGenerationUtils._
import scala.collection.{IndexedSeq, mutable}
object FieldsEditor{
  import com.redhat.certgen.Utils.implicits._
  trait ObjectEditor{
    def printAll{}
    def printAvailable{}
    def editableFields: Option[IndexedSeq[String]] = None
    def editorFor(property: String): ObjectEditor = DumbEditor
    def isSimple: Boolean = true
    def done(parent: ObjectEditor){}
  }

  trait ComplexEditor extends ObjectEditor{
    override def isSimple: Boolean = false
  }

  trait SimpleEditor extends ObjectEditor{
    override def isSimple : Boolean = true
    def update(str: String, value: String):Unit
  }

  object DumbEditor extends ObjectEditor

  class GenericCertEntityEditor(entity: GenericCertificateEntity) extends ComplexEditor{
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
      override def update(str: String, value: String):Unit 
	= entity(Symbol(str)) = value
    }
    def setValue(sym: Symbol, value: String){
      entity(sym) = value
    }
  }

 class MultiElementsEditor(elements: mutable.Buffer[GenericCertificateEntity]) extends ComplexEditor{
   override def printAll{
     println("\nTotal number of elements: " + elements.size)
     println(elements.mkString("|elements begin|", elements.mkString("\n"), "|elements end|"))
   }

   override def printAvailable = printAll
   override def editableFields = 
     Some(new scala.collection.immutable.Range(0, elements.size, 1).map("" + _))

   override def editorFor(property: String): ObjectEditor = {
     if(Integer.parseInt(property) > elements.size){
       println("[Error] Input index exceeds > #" + elements.size)
       return DumbEditor
     }else{
       return new GenericCertEntityEditor(elements(property))
     }
   }
 }

 class CertificateEditor(cert: Certificate) extends ComplexEditor{
   private lazy val dtParser = new java.text.SimpleDateFormat("MM/dd/yyyy")
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
   override def editorFor(property: String): ObjectEditor = {
     val method = readMethods.find(_.getName == property)
     val bufrClass = classOf[mutable.Buffer[_]]
     val dClass = classOf[java.util.Date]
     val strClass = classOf[String]
     val optClass = classOf[Option[_]]
     method match {
       case Some(m) =>
	 m.getReturnType match {
	   case `bufrClass` => 
	     new MultiElementsEditor(m.invoke(cert)
				     .asInstanceOf[mutable.Buffer[GenericCertificateEntity]])
	   case `strClass` => new SimpleEditor{
	     override def update(str: String, value: String):Unit = {
	       cert.subjectDN = value //forgive me here! will change it to be more generic later
	     }
	   }
	   case `dClass` => new SimpleEditor{
	     override def update(str: String, value: String):Unit = {
	       try{
		 val dt = dtParser.parse(value)
		 if(property == "startDate")
		   cert.startDate = dt
		 else
		   cert.endDate = dt
	       }catch {
		 case e: Exception =>
		   println("Date should be in format: MM/dd/yyyy. (01/12/2010)")
	       }
	     }
	   }
	   case `optClass` =>
	     val toEdit = m.invoke(cert)
	     toEdit match {
	       case Some(gce) => new GenericCertEntityEditor(gce.asInstanceOf[GenericCertificateEntity])
	       case None => DumbEditor

	     }
	   case _ => DumbEditor
	 }
       case None => DumbEditor
    }
  }
 }

}



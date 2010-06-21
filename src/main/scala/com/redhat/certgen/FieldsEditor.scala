package com.redhat.certgen
import com.redhat.certgen.CertificateGenerationUtils._
import scala.collection.{IndexedSeq, mutable}
import com.redhat.certgen.Utils.implicits._
object FieldsEditor{

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
     val bIntClass = classOf[java.math.BigInteger]
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
	   case `bIntClass` =>
	     new SimpleEditor{ //hard coded reference to serial -- will change later
	       override def update(str: String, value: String): Unit = {
		 try { cert.serial = new java.math.BigInteger(value) }
		 catch{
		   case _ => println("\nUnable to convert " + value + " to BigInteger. Input should be an integer")
		 }
	       }
	     }
	   case _ => DumbEditor
	 }
       case None => DumbEditor
    }
  }
 }

}

class CMDFacade(val cert: Certificate){
  import com.redhat.certgen.FieldsEditor._
  import java.lang.System.console
  def this(x509Cert: java.security.cert.X509Certificate) = this(Certificate(x509Cert))
  private val editorStack = new scala.collection.mutable.ArrayStack[ObjectEditor]
  editorStack.push(new CertificateEditor(cert))

  def evalLoop{
    def printOptions{
      console.printf("\nedit => Edit value(s) within the certificate")
	.printf("\nprint => Print current level values")
	.printf("\nprint-all => Print all the available fields/values within the current entity")
	.printf("\nback => Go back one level")
	.printf("\nsave => Save the certificate to file")
	.printf("\nhelp => Print help").printf("\nquit => Quit the utility")
    }
    console.printf("\nCertificate has been successfully loaded! Enter help for more options")
    var shouldExit = false
    while(!shouldExit){
      console.readLine("\nrh>").toLowerCase match {
	case "help"| "h" => printOptions
	case "print" | "p" => editorStack.head.printAvailable
	case "print-all" | "pa" => editorStack.head.printAll
	case "edit" | "e" => 
	  val availableFields = editorStack.head.editableFields
	  availableFields match {
	    case Some(list) if list.size > 0 =>
	      list.zipWithIndex.foreach({ tupl => console.printf("\n\t[%d].%s", Integer.valueOf(tupl._2), tupl._1)})
	      console.printf("\nEnter the numbers to edit the field")
	      console.readLine("\nrh>") match{
		case "quit" | "q" => console.printf("\nCancelled editing current entity")
		case no: String => 
		  val editor = editorStack.head.editorFor(list(no.trim)) 
		  editor match {
		    case DumbEditor => console.printf("\nSorry! no editor found for %s", list(no.trim))
		    case simple: SimpleEditor => 
		      val value = console.readLine("\nrh:value[%s]=>", list(no.trim))
		    if(value.trim.length == 0){
		      console.printf("\nNo value entered. Ignoring edit")
		    }else{
		      simple.update(list(no.trim), value)
		      console.printf("\nValue updated.")
		    }
		    case complex: ComplexEditor => 
		      editorStack.push(complex)
		      console.printf("\nLoaded entity")
		      editorStack.head.printAvailable
		  }
	      }
	    case None | _ => console.printf("\nCurrent entry is not editable(yet)!")
	  }

	case "back" | "b" =>
	  if(editorStack.size > 1){
	    val prevEditor = editorStack.pop
	    prevEditor.done(editorStack.head)
	  }else{
	    console.printf("\nCannot go back any more levels!")
	  }
	case "quit" | "q" =>
	  console.printf("\nQuitting!")
	  shouldExit = true
	case "save" => 
	  val file = console.readLine("\nrh>Enter the file name to save the modified certificate into: ")
	  if(file.trim.length == 0)
	    console.printf("\nFile name not valid! Ignoring...")
	  else{
	   try{ 
	     Utils.writeToFile(file, Certificate.toX509(cert)) 
	     console.printf("\nModified certificate saved successfully to %s", file)
	   }catch {
	     case e: Exception => console.printf("\nUnable to save certificate to file %s", file); e.printStackTrace
	     
	   }
	  
	  }
	case _ =>  console.printf("\nInvalid option! Please try again")
      }
    }
  }

}

object CLI{
 
  def main(args: Array[String]):Unit = {
    import java.security.cert.X509Certificate
    def loadCert(path: String): X509Certificate ={
      val in = new java.io.FileInputStream(path)
      java.security.cert.CertificateFactory.getInstance("X509")
	.generateCertificate(in).asInstanceOf[X509Certificate]
    }
    if(args.length < 1){
      println("Usage: cli <certificate_path>")
      return
    }
    val x509Cert = loadCert(args(0))
    new CMDFacade(Certificate(x509Cert)).evalLoop
  }

}

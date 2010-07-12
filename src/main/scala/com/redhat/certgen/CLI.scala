package com.redhat.certgen
import com.redhat.certgen.editor._
import com.redhat.certgen.certificate.{GenericCertificateEntity, Certificate}
import com.redhat.certgen.Utils.implicits._
class CMDFacade(val cert: Certificate){
  import java.lang.System.console
  def this(x509Cert: java.security.cert.X509Certificate) = this(Certificate(x509Cert))
  private val editorStack = new scala.collection.mutable.ArrayStack[ComplexEditor]
  editorStack.push(CertificateEditor(cert))

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
		      simple.apply(value)
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

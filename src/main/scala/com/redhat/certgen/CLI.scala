package com.redhat.certgen
import com.redhat.certgen.editor._
import com.redhat.certgen.certificate.{GenericCertificateEntity, Certificate}
import com.redhat.certgen.Utils.implicits._
import scala.collection.mutable
class CMDFacade(val cert: Certificate){
  import java.lang.System.console
  import java.lang.String.format
  def this(x509Cert: java.security.cert.X509Certificate) = this(Certificate(x509Cert))
  private val editorStack = new scala.collection.mutable.ArrayStack[Editor]
  editorStack.push(CertificateEditor(cert))
  implicit def editorToPrintable(s: Editor) = new Printable{
    override def printAll{
      s match{
	case c: Printable => c.printAll
	case simple: SimpleEditor => console.printf(simple.asText)
	case _ =>
      }
    }

    override def printAvailable{
      s match{
	case c: Printable => c.printAvailable
	case simple: SimpleEditor => console.printf(simple.asText)
	case _ =>
      }
    }
  }
  def question(str: String) = new {
    private var yes: () => Unit = {() => Unit}
    private var no: () => Unit = {() => Unit}
    def ask{
      console.readLine(str) match{
	case "y"|"Y"|"Yes"|"yes" => yes
	case "n"|"N"|"No"|"no"|_ => no
      }
    } 
    def ifYes(func: => Unit) = {
      this.yes = func _
      this
    }
    def ifNo(func: => Unit) = {
      this.no = func _
      this
    }
  }
  def evalLoop{
    def pushEditorIntoStack(e: Editor){
      editorStack.push(e)
      console.printf("Loaded entity...")
      e.printAvailable
    }
    def printOptions{
      console.printf("\nedit - Edit value(s) within the certificate")
	.printf("\nprint - Print current level values")
	.printf("\nprint-all - Print all the available fields/values within the current entity")
	.printf("\nback - Go back one level")
	.printf("\nsave - Save the certificate to file")
        .printf("\nadd - Add new item to the currently selected entity")
        .printf("\ndelete - Delete existing entity or index")
	.printf("\nhelp - Print help").printf("\nquit - Quit the utility")
    }
    def editSimpleField(simple: SimpleEditor){
      val value = console.readLine("\ncert-gen>value=")
      if(value.trim.length == 0){
	  console.printf("\nNo value entered. Ignoring edit")
       }else{
	 simple.apply(value)
   	 console.printf("\nValue updated to %s", simple.asText)
       }
    }
    def goBack{
      if(editorStack.size > 1){
	editorStack.pop match {
	  case c: ComplexEditor => c.done(editorStack.head)
	  case _ =>
	}
      }else{
	console.printf("\nCannot go back any more levels!")
      }
    }
    console.printf("\nCertificate has been successfully loaded! Enter help for more options")
    var shouldExit = false
    while(!shouldExit){
      console.readLine("\ncert-gen>").toLowerCase match {
	case "help"| "h" => printOptions
	case "print" | "p" => editorStack.head.printAvailable
	case "print-all" | "pa" => editorStack.head.printAll
	case "edit" | "e" => 
	  editorStack.head match {
	    case complex: ComplexEditor =>
	      val availableFields = complex.editableFields
	      availableFields match {
		case Some(list) if list.size > 0 =>
		  list.zipWithIndex.foreach({ tupl => 
		    console.printf("\n  [%d].%s", Integer.valueOf(tupl._2), tupl._1)
		  })
		  console.printf("\nEnter the numbers to edit the field")
		  console.readLine("\ncert-gen>") match{
		    case "quit" | "q" => 
		      console.printf("\nCancelled editing current entity")
		    case no: String => 
		      complex.editorFor(list(no.trim)) match {
			case DumbEditor => 
			  console.printf("\nSorry! no editor found for %s", list(no.trim))
			case simple: SimpleEditor => 
			  editSimpleField(simple)
			case complex: ComplexEditor => 
			  pushEditorIntoStack(complex)
			case opt: OptionEditor =>
			  if(!opt.exists){
			    question(list(no.trim)+" does not exists. Create it?(y/N)")
			       .ifYes{ pushEditorIntoStack(opt.edit) }
			       .ifNo {
				  console.printf("\n%s not created..!", list(no.trim))
				}.ask

			  }else{
			    pushEditorIntoStack(opt.edit)
			  }
		    }
		  }
	      case None | _ => 
		console.printf("\nNo items available for editing. You could try 'add'")
	    }

	    case opt: OptionEditor =>
	      if(!opt.exists){
		console.printf("\nCurrently entry does not exist. Do you want to create&edit?")
	      }
	    pushEditorIntoStack(opt.edit)

	    case simple: SimpleEditor =>
		editSimpleField(simple)
		goBack
	  }
	case "back" | "b" => goBack	 
	case "quit" | "q" =>
	  console.printf("\nQuitting!")
	  shouldExit = true
	case "save" => 
	  val file = console.readLine("\ncert-gen>Enter the file name to save the modified certificate into: ")
	  if(file.trim.length == 0)
	    console.printf("\nFile name not valid! Ignoring...")
	  else{
	   try{ 
	     Utils.writeToFile(file, Certificate.toX509(cert)) 
	     console.printf("\nModified certificate saved successfully to %s", file)
	   }catch {
	     case e: Exception => 
	       console.printf("\nUnable to save certificate to file %s. see /tmp/certgen.log for details..",
			      file); 
	       e.printStackTrace
	   }
	  }
	case "add" =>
	  editorStack.head match {
	    case ed: SequenceContainerEditor =>
	      pushEditorIntoStack(ed.add)
	    case _ => 
	      console.printf("\nCurrent entry does not support add")
	  }
	case "delete" =>
	  editorStack.head match{
	    case ed: SequenceContainerEditor =>
	      console.readLine("\nEnter index to delete(q to cancel): ") match {
		case "q" => 
		case no: String  =>
		  ed.delete(no)
		  console.printf("%s deleted", no)
		  ed.printAvailable
		case _ => //heh?
	      }
	    case opt: OptionEditor =>
	      question("\nAre you sure you want to delete(y/N)?")
		.ifYes{
		  opt.delete
		  console.printf("deletion successful!")
		}.ask
	    case _ =>
	      console.printf("\nCurrent entry does not support delete")
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

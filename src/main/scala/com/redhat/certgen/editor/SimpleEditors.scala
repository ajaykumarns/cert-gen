package com.redhat.certgen.editor
class DateEditor(fmt: String) extends SimpleEditorSupport{
  def this() = this("MM/dd/yyyy")
  val parser = new java.text.SimpleDateFormat(fmt)
  override def apply(str: String){
    try{ methods.setter.invoke(this.instance, parser.parse(str))}
    catch{
      case e: Exception =>
        println("Date should be in format: " + fmt)
    }
  }
}
class IntEditor extends SimpleEditorSupport{
  override def apply(str: String){
    try{ methods.setter.invoke(this.instance, Integer.parseInt(str).asInstanceOf[AnyRef])}
    catch{
      case no: NumberFormatException => println("Input should be a number")
    }
  } 
}


class BigIntEditor extends SimpleEditorSupport{
  override def apply(str: String){
    try{ methods.setter.invoke(this.instance, new java.math.BigInteger(str)) }
    catch{
      case _ => println("Unable to convert:" + str + " to BigInteger. Should be a number")
    }
  }
}


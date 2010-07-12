package com.redhat.certgen.editor
import com.redhat.certgen.CertificateGenerationUtils._
import scala.collection.{IndexedSeq, mutable}
import com.redhat.certgen.Utils.implicits._

case class MethodPair(getter: Method, setter: Method)
trait Editor{
    //marker interface
}

object DumbEditor extends Editor

trait SimpleEditor extends Editor with (String => Unit){
  def asText: String
  def defaultValue: Option[String] = None
}

trait OptionEditor extends Editor{
  def delete:Unit
  def edit: Editor
  def exists: Boolean
}

trait ComplexEditor extends Editor{
  def printAll{}
  def printAvailable{}
  def editableFields: Option[IndexedSeq[String]] = None
  def editorFor(property: String): Editor = DumbEditor
  def done(parent: Editor){}
}

//TODO : Is it really a complex editor? editorFor() is broken.
trait SequenceContainerEditor extends ComplexEditor{
  def delete(index: Int): Unit
  def add: Editor
}

trait EditorSupport extends Editor{
  var instance: Any = _
  var propertyDescriptor = _
  def methods: MethodPair =
    MethodPair(propertyDescriptor.getReadMethod, propertyDescriptor.getWriteMethod)
  protected def toBeEditedEntity = methods.getter.invoke(instance)
  
  protected def getAnn(clas: Class[_]) = 
    instance.getClass.getDeclaredField(propertyDescriptor.getName).getAnnotation(clas)
}


trait SimpleEditorSupport extends SimpleEditor with EditorSupport{
  override def asText = {
    val obj = methods.getter.invoke(instance)
    if(obj == null) "" else obj.toString
  }
  override def apply(str: String):Unit =
      methods.setter.invoke(instance, str)
}

class StringEditor extends SimpleEditorSupport
//TODO: No support provided at the moment...
trait ComplexEditorSupport extends ComplexEditor with EditorSupport{
  
}

trait SequenceContainerEditorSupport extends SequenceContainerEditor with EditorSupport{
  override def delete(index: Int):Unit = { 
    val bufr = this.instance.asInstanceOf[scala.collection.mutable.BufferLike]
    if(index > bufr.size){
      println(String.format("Cannot delete %dth element. Input index exceeds > # %d",
                    index, bufr.size))
    }else{
      bufr.remove(index)
    }
  }
}

trait OptionEditorSupport extends OptionEditor with EditorSupport{
  override def exists = toBeEditedEntity != None
  override def delete:Unit{
    methods.setter.invoke(instance, None)
  }
}
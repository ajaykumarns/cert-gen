package com.redhat.certgen.editor
import com.redhat.certgen.editor._
object EditorFactory{

  def editorsFor(obj: AnyRef):mutable.Map[String, Editor] = {
      val editorMap = new mutable.HashMap[String, Editor]
      val (btProps, nbtProps) = Introspector.getBeanInfo(obj.getClass)
            .getPropertyDescriptors.partition {pd: PropertyDescriptor =>
                pd.getReadMethod != null && pd.getWriteMethod !=null
            }
      btProps.foreach {pd:PropertyDescriptor => 
        editorMap(pd.getName) = editorFor(obj, pd)
      }
  
      nbtProps.filter(pd => pd.getReadMethod != null && pd.getName != "class")
        .foreach {case pd:PropertyDescriptor =>
          val cEditor = tryCreatingCustomEditor(obj, pd)
          if(cEditor != null)
            editorMap(pd.getName) = cEditor
        }
      editorMap
    }
    private val editors:Map[Class[_], Class[_]] = Map(
      (classOf[String] -> classOf[StringEditor]),
      (classOf[java.math.BigInteger] -> classOf[BigIntEditor]),
      (classOf[java.util.Date] -> classOf[DateEditor]),
      (classOf[Option] -> classOf[GenericOptionEditor])
    )
    def editorFor(obj: AnyRef, pd: PropertyDescriptor): Editor = {
      editors.get(pd.getReadMethod.getReturnType) match {
        case Some(x) => createEditor(x, obj, pd)
        case _ => tryCreatingCustomEditor(obj, pd)
      }
    }
    
    def editorFor(obj: AnyRef, property: String): Editor = 
      Introspector.getBeanInfo(obj.getClass).getPropertyDescriptors
      .find(_.getName == property) match {
        case Some(pd) => editorFor(obj, pd) 
        case None => DumbEditor
      }
    
    private def tryCreatingCustomEditor(obj: AnyRef, pd: PropertyDescriptor) = {
      try{
       val clas = obj.getClass.getDeclaredField(pd.getName).getAnnotation(classOf[UseEditor])
        if(clas != null){
          createEditor(clas.asInstanceOf[UseEditor].editor, obj, pd)
        }
      }catch{
        e: NoSuchFieldException => 
      }
      DumbEditor
    }
    private def createEditor(editorClas: Class[_], obj: AnyRef, pd: PropertyDescriptor) = {
       val editor = editorClas.newInstance.asInstanceOf[PropertyEditor]
       editor.instance = obj 
       editor.propertyDescriptor = pd 
       editor 
    }
  
}
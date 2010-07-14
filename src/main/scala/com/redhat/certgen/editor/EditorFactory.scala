package com.redhat.certgen.editor
import java.beans._
import scala.collection.mutable
import com.github.certgen.annotations._
object EditorFactory{
  val logger = com.redhat.certgen.Utils.loggerFor(getClass)
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
      (classOf[Option[_]] -> classOf[GenericOptionEditor])
    )
    def editorFor(obj: AnyRef, pd: PropertyDescriptor): Editor = {
      logger.debug("editorFor: {}, property: {}", obj.getClass, pd.getName)
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
    
    private def tryCreatingCustomEditor(obj: AnyRef, pd: PropertyDescriptor):Editor = {
      logger.debug("Trying to create custom editor for {}#{}", obj.getClass, pd.getName)
      try{
       logger.debug("Annotations of {}: {}", pd.getName, 
		    obj.getClass.getAnnotations.map(_.annotationType).mkString(","))
       val clas = obj.getClass.getDeclaredField(pd.getName).getAnnotation(classOf[UseEditor])
       logger.debug("UseEditor annotation: {}", clas)
        if(clas != null){
          return createEditor(clas.asInstanceOf[UseEditor].editor, obj, pd)
        }
      }catch{
        case e: NoSuchFieldException => 
	  logger.error("Error while trying to create custom editor for" + pd.getName,e)
      }
      DumbEditor
    }
    private def createEditor(editorClas: Class[_], obj: AnyRef, pd: PropertyDescriptor) = {
       val editor = editorClas.newInstance.asInstanceOf[EditorSupport]
       editor.instance = obj 
       editor.propertyDescriptor = pd 
       editor 
    }
  
}

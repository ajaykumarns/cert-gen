package com.redhat.certgen.certificate
import scala.collection.mutable
import com.redhat.certgen.ExtensionSupport._
import com.redhat.certgen.Utils.implicits._
trait CertificateEntity{
  def fields: scala.collection.IndexedSeq[Symbol]
}

class GenericCertificateEntity(val symbol: Symbol, var namespace: String)
extends CertificateEntity{
  import GenericCertificateEntity.logger
  def this(symbol: Symbol) = this(symbol, null)
  override val fields:scala.collection.IndexedSeq[Symbol] =
	  GenericCertificateEntity.certificateFieldsMap(symbol)
  private val map: mutable.Map[Symbol, String] = new mutable.HashMap
  def \ (str: Symbol): Option[String] =
    if(map.contains(str)) Some(map(str)) else None
  def update(sym: Symbol, str: String){
    map.put(sym, str)
    logger.debug("Update called {} = {}", sym.name, str)
  }
  override def toString = 
    String.format("[%s] namespace=%s | values = %s", symbol, namespace, map.mkString("\n"))  
}

object GenericCertificateEntity{
  val logger = com.redhat.certgen.Utils.loggerFor(getClass)
  import com.redhat.certgen.Node
  val contentEntity = 'Content
  val orderEntity = 'Order
  val productEntity = 'Product
  val systemEntity = 'System
  val roleEntity = 'Role

  val certificateFieldsMap = Map(
    (contentEntity -> Array('name, 'label, 'physical, 'flexGuest, 'vendorId,
			    'downloadUrl, 'gpgKeyUrl, 'enabled)),
    (productEntity -> Array('name, 'variant, 'architecture, 'version)),
    (roleEntity -> Array('name, 'label, 'quantity)),
    (orderEntity -> Array('name, 'orderNo, 'sku, 'subscriptionNo, 'quantity,
			  'entitlementStartDt, 'entitlementEndDt, 'subType, 'virtualizationLimit, 'socketLimit, 'productOptionCode,
			  'contractNumber, 'quantityUsed)),
    (systemEntity -> Array('uuid, 'hostUUID))
  )

  val certificateToFieldEntityMap: Map[Symbol, Map[Symbol, Int]] = Map(
    (contentEntity -> certificateFieldsMap(contentEntity).zipWithIndex.toMap),
    (productEntity -> certificateFieldsMap(productEntity).zipWithIndex.toMap),
    (roleEntity -> certificateFieldsMap(roleEntity).zipWithIndex.toMap),
    (orderEntity -> certificateFieldsMap(orderEntity).zipWithIndex.toMap),
    (systemEntity -> certificateFieldsMap(systemEntity).zipWithIndex.toMap)
  )

  val certificateToFieldEntityMapRev: Map[Symbol, Map[Int, Symbol]] =
    certificateToFieldEntityMap.map({case (k, v) => (k, v.map(_.swap))})

  implicit def strToNamespace(str: String) = new {
    def extend(extension: String) = str + "." + extension
  }

  def toExtensions(entity: GenericCertificateEntity): Iterable[X509Extn] = {
    val extensions: mutable.Buffer[X509Extn] = new mutable.ArrayBuffer
    if (!certificateToFieldEntityMap.contains(entity.symbol))
      throw new RuntimeException("Cannot translate entity " + entity.symbol + " to extensions")
    certificateToFieldEntityMap(entity.symbol).foreach {
      case (symb: Symbol, index: Int) =>
        entity \ symb match {
          case Some(value) => extensions += X509Extn(entity.namespace.extend(index + 1), false, value)
          case None =>
        }
    }
    return extensions
  }

  def apply(sym: Symbol, str: String) = new GenericCertificateEntity(sym, str)
  def apply(sym: Symbol, node: Option[TrieNode]): Option[GenericCertificateEntity] = node match{
    case Some(n) => Some(apply(sym, n))
    case None => None
  }
  def apply(symb: Symbol, node: TrieNode): GenericCertificateEntity = {
    //println(node)
    def setFields(entity: GenericCertificateEntity) = {
      val fields: Map[Int, Symbol] = certificateToFieldEntityMapRev(entity.symbol)
      for( (pos, node) <- node.children.getOrElse({new mutable.HashMap[String, TrieNode]})){
        logger.debug(pos + "." + node)
        entity(fields(pos.trim - 1)) = new String(node.value)
      }
      entity
    }
    def toOrder = setFields(GenericCertificateEntity(orderEntity, namespace.order))
    def toProduct = setFields(GenericCertificateEntity(productEntity, node.fullExtension))
    def toContent = setFields(GenericCertificateEntity(contentEntity, node.fullExtension))
    def toSystem = setFields(GenericCertificateEntity(systemEntity, namespace.system))
    def toRole = setFields(GenericCertificateEntity(roleEntity, node.fullExtension))

    symb match {
      case `orderEntity`  => toOrder
      case `contentEntity` => toContent
      case `productEntity` => toProduct
      case `systemEntity` => toSystem
      case `roleEntity` => toRole
      case _ => throw new RuntimeException("Unknown entity :" + symb)
    }
  }
  def toExtensions(entities: Iterable[GenericCertificateEntity]): Iterable[X509Extn]
  = entities.flatMap(toExtensions)
}

package com.redhat.certgen
import java.security._
import java.security.cert._
import org.bouncycastle.x509.extension._
import org.bouncycastle.asn1._
import org.bouncycastle.jce._
import java.util.Date
import scala.collection._
import org.bouncycastle.asn1.x509._
import javax.security.auth.x500.X500Principal
case class DateRange(startDate: Date, endDate: Date)
case class KeyAndCertificate(key: PrivateKey, certificate: X509Certificate)
case class X509Extn(oid: String, critical: Boolean, asn1Encodable: ASN1Encodable)

object CertificateGenerationUtils{
  import com.redhat.certgen.Utils.implicits._
  import org.bouncycastle.asn1.x509.KeyUsage._
  import org.bouncycastle.asn1.misc._
  import java.util.UUID.randomUUID
  lazy val keyFactory  = createRSAKeyFactory
  val currentDateRange = DateRange(new Date(), (new Date()).oneYearAhead)
  def createRSAKeyFactory = {
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator
  }

  def createX509Cert(principal: X500Principal = new X500Principal(createDN()),
		     dtRange: DateRange = currentDateRange,
                     pbKey: PublicKey, keyCert: Option[KeyAndCertificate] = None,
                     extensions: Option[Iterable[X509Extn]] = None): X509Certificate = {

    val gen = new org.bouncycastle.x509.X509V3CertificateGenerator()
    gen.setSerialNumber(new java.math.BigInteger("" + scala.math.abs(new java.util.Random().nextInt)))
    gen.setNotBefore(dtRange.startDate)
    gen.setNotAfter(dtRange.endDate)
    gen.setSubjectDN(principal)
    gen.setPublicKey(pbKey)
    gen.setSignatureAlgorithm("SHA1WITHRSA")

    gen.addExtension(MiscObjectIdentifiers.netscapeCertType.toString(),
		     false, new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.smime))
    gen.addExtension(X509Extensions.KeyUsage.toString(), false,
		     new KeyUsage( digitalSignature | keyEncipherment | dataEncipherment))
    gen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		     new SubjectKeyIdentifierStructure(pbKey))
    extensions match {
      case Some(exs) => exs.foreach {e:X509Extn => gen.addExtension(e.oid, e.critical, e.asn1Encodable) }; println("extensions size : " + exs.size)

      case None =>
    }
    keyCert match {
      case Some(kc) =>
        gen.setIssuerDN(kc.certificate.getSubjectX500Principal)
	gen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
		       new AuthorityKeyIdentifierStructure(kc.certificate))
	return gen.generate(kc.key)
      case None =>
        gen.setIssuerDN(principal)
        return gen.generate(keyFactory.generateKeyPair.getPrivate)
    }
  }


 def createDN(consumerName: String = randomUUID.toString, usrName: String = randomUUID.toString,
               uuid: String = randomUUID.toString) =
    String.format("CN=%s, UID=%s, OU=%s", consumerName, usrName, uuid)

  def createRandomX509CertAndKey: KeyAndCertificate = {
    val keyPair = keyFactory.generateKeyPair

    KeyAndCertificate(keyPair.getPrivate,
		      createX509Cert(pbKey = keyPair.getPublic))
  }

  trait X509ExtnSupport{
    val redhatOID = "1.3.6.1.4.1.2312.9"
    def namespace:String
    def + (ex: String, value: String) : X509ExtnSupport = {
      bufr += X509Extn(namespace + "." + ex, false, value)
      return this
    }
    private val bufr = new mutable.ArrayBuffer[X509Extn]
    def toX509Extn: mutable.Buffer[X509Extn] = bufr
  }


  case class Product(hash: Int, name: String, variant: String, arch: String, version: String)
       extends X509ExtnSupport{
	 override val namespace = "1.3.6.1.4.1.2312.9." + hash
	 this + (1, name) + (2, variant) + (3, arch) + (4, version)
       }

  case class System(uuid: String, hostUUID: String){
    def this(uuid: String) = this(uuid, null)
    def toX509Extn: mutable.Buffer[X509Extn] =
      new mutable.ArrayBuffer[X509Extn] += X509Extn("1.3.6.1.4.1.2312.9.5", false, uuid)
  }

  case class Order(name: String, orderNo: Int, dRange: DateRange = currentDateRange, cNo: Int, qUsed: Int, quantity: Int)
     extends X509ExtnSupport{
    override val namespace = "1.3.6.1.4.1.2312.9.4"
    this + (1, name) + (2, orderNo) + (5, quantity) + (6, dRange.startDate) + (7, dRange.endDate) + (12, cNo) + (13, qUsed)

  }
  case class Content(id: String, _type: String, name: String, labl: String, vendor: String, contentUrl: String, gpgUrl: String, enabled: Boolean)
       extends X509ExtnSupport{
     override val namespace = redhatOID + ".2." + id + "." + (if(_type.toLowerCase == "yum") 1 else 2)

     this + (1, name) + (2, labl) + (5, vendor) + (6, contentUrl) + (7, gpgUrl) + (8, enabled)

  }

  trait CertificateEntity{
    def fields: scala.collection.IndexedSeq[Symbol]
  }

  class GenericCertificateEntity(val symbol: Symbol, var namespace: String)
          extends CertificateEntity{
    def this(symbol: Symbol) = this(symbol, null)
    override val fields:scala.collection.IndexedSeq[Symbol] = GenericCertificateEntity.certificateFieldsMap(symbol)
    private val map: mutable.Map[Symbol, String] = new mutable.HashMap
    def \ (str: Symbol): Option[String] =
      if(map.contains(str)) Some(map(str)) else None
    def update(sym: Symbol, str: String):Unit = map.put(sym, str)

    override def toString = String.format("[%s] namespace=%s | values = %s", symbol, namespace, map.mkString("\n"))
  }

  object GenericCertificateEntity {
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
            case Some(value) => extensions += X509Extn(entity.namespace.extend(index), false, value)
            case None =>
          }
      }
      return extensions
    }
    import ExtensionSupport._
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
          //println(pos + "." + node)
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
    def toExtensions(entities: Iterable[GenericCertificateEntity]): Iterable[X509Extn] = entities.flatMap(toExtensions)
    
  }

  @scala.reflect.BeanInfo class Certificate{
    import ExtensionSupport._
    val contents:mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer
    val roles: mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer
    var system: Option[GenericCertificateEntity] = None
    var order: Option[GenericCertificateEntity] = None
    val products: mutable.Buffer[GenericCertificateEntity] = new mutable.ArrayBuffer
    var startDate = new Date()
    var endDate = (new Date()).oneYearAhead
    var serial = new java.math.BigInteger(new java.util.Random().nextInt)
    var publicKey: PublicKey = _
    var subjectDN = createDN()

    override def toString = {
      val bufr = new StringBuilder
      bufr.append("\n|Certificate|\n beginDate = ")
          .append(startDate).append(", endDate = ").append(endDate)
          .append("\nSerial = ").append(serial)
      if(contents.size > 0) bufr.append(contents.mkString("\n|Contents|\n", "\n", "\n------------\n"))
      if(roles.size > 0)    bufr.append(roles.mkString("\n|Roles|\n", "\n", "\n------------\n"))
      if(system != None)    bufr.append(system.get.toString).append("\n")
      if(order != None)     bufr.append(order.get.toString).append("\n")
      if(products.size > 0) bufr.append(products.mkString("\n|Products|\n", "\n", "\n------------\n"))
      bufr.toString
    }
  }
  object Certificate{
    import ExtensionSupport._
    def apply(cert: X509Certificate) = {
      val certificate = new Certificate
      val rhTrie = RedHatNode(cert)
      println("Order : " + namespace.order)
      certificate.order = GenericCertificateEntity('Order, rhTrie \ namespace.order)
      certificate.system = GenericCertificateEntity('System, rhTrie \ namespace.system)
      certificate.startDate = cert.getNotBefore
      certificate.endDate = cert.getNotAfter
      certificate.serial = cert.getSerialNumber
      certificate.publicKey = cert.getPublicKey
      certificate.subjectDN = cert.getSubjectDN.toString
      rhTrie \ namespace.product match {
        case Some(node) if node.children != None =>
          for(product <- node.children.get){
            certificate.products += GenericCertificateEntity('Product, product._2)
          }
        case None | _ =>
      }

      rhTrie \ namespace.content match { //content namespace level
        case Some(node) if node.children != None =>
          for(content <- node.children.get){ //content hash level.
            for(child <- content._2.children.get){  //for same content, there could be more than single repo type
              certificate.contents += GenericCertificateEntity('Content, child._2)
            }
          }
        case None | _ =>
      }

      rhTrie \ namespace.role match {
        case Some(node) if node.children != None =>
          for(role <- node.children.get){
            certificate.roles += GenericCertificateEntity('Role, role._2)
          }
        case None | _ =>
      }
      certificate
    }

    def toX509(cert: Certificate, keyCert: Option[KeyAndCertificate] = None): X509Certificate = {
      import GenericCertificateEntity.toExtensions
      val extensions: mutable.Buffer[X509Extn] = new mutable.ArrayBuffer
      extensions ++= toExtensions(cert.contents) ++= toExtensions(cert.roles) ++= toExtensions(cert.products)
      cert.system match{ case Some(system) => extensions ++= toExtensions(system); case None => }
      cert.order match{ case Some(order) => extensions ++= toExtensions(order); case None => }
      createX509Cert(new X500Principal(cert.subjectDN), DateRange(cert.startDate, cert.endDate), 
		     cert.publicKey, keyCert, Some(extensions))
    }
  }

  //implicit def xcertToCert(cert: X509Certificate): Certificate = new Cer

}


object Main extends Application{
  import Utils.implicits.{dumpByteIntoFile, imKeyToBytes, intToStr, xCertToBytes}
  import CertificateGenerationUtils._
  // val kc = CertificateGenerationUtils.createRandomX509CertAndKey
  // println(new String(kc.key))
  // println(new String(kc.certificate))
  val keyPair = keyFactory.generateKeyPair
  val extensions:mutable.Buffer[X509Extn] = new mutable.ArrayBuffer[X509Extn]
  (extensions ++=
          Order(name="Red Hat ENterprise Linux Server", orderNo=12345, cNo=152341643, qUsed=4, quantity=100).toX509Extn
          ++= new System(java.util.UUID.randomUUID.toString).toX509Extn
          ++ Product(8251, "Red Hat Enterprise Linux", "Server", "x86_64", "6.0").toX509Extn
          ++= Content(789, "yum", " Red Hat Enterprise Linux (Supplementary)",
		            "rhel-server-6-supplementary", "%Red_Hat_Id% or %Red_Hat_Label%", "content/rhel-server-6-supplementary/$releasever/$basearch", "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release", true).toX509Extn);


  val kc1 = KeyAndCertificate(keyPair.getPrivate,
		      createX509Cert(pbKey = keyPair.getPublic, extensions = Some(extensions)))
  "/home/ajay/tmp/key.pem" << kc1.key
  "/home/ajay/tmp/cert.pem" << kc1.certificate
 // "/home/ajay/tmp/cert1.pem" << kc.certificate
  val trie = ExtensionSupport.RedHatNode.toTrie(kc1.certificate)
  val testCert = Certificate(kc1.certificate)

  //println(Certificate.toX509(cert = testCert))
  val editor = new com.redhat.certgen.FieldsEditor.CertificateEditor(testCert)
  println(editor.editableFields)
  println(editor.editorFor("startDate").asInstanceOf[FieldsEditor.SimpleEditor].update("startDate", "02/02/2001"))
  println(testCert)
}

